using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace b17s.Porta.Tests.Integration;

/// <summary>
/// Stubbed OIDC authority. Hosts discovery, JWKS, authorize, token, userinfo,
/// revocation, and RFC 7662 introspection endpoints with deterministic behavior
/// so the BFF pipeline can be exercised end-to-end without a real IdP.
/// </summary>
public sealed class FakeIdp : IDisposable
{
    private readonly IHost _host;
    private readonly TestServer _testServer;
    private readonly RsaSecurityKey _signingKey;
    private readonly ConcurrentDictionary<string, IssuedCode> _codes = new();
    private readonly ConcurrentDictionary<string, IssuedRefresh> _refreshTokens = new();
    private readonly HashSet<string> _revokedTokens = new(StringComparer.Ordinal);
    private readonly Lock _revokedLock = new();
    private readonly ConcurrentDictionary<string, int> _exchangeCallsByAudience = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ReferenceTokenRecord> _referenceTokens = new(StringComparer.Ordinal);
    private int _exchangeCalls;
    private int _refreshGrantCalls;
    private int _revocationCalls;
    private int _introspectionCalls;

    public string Authority { get; }
    public string ClientId { get; }
    public string ClientSecret { get; }
    public HttpMessageHandler BackchannelHandler { get; }
    public HttpClient FrontchannelClient { get; }

    /// <summary>The user the next authorize call will issue tokens for.</summary>
    public ClaimsIdentity NextUserIdentity { get; set; } = MakeDefaultIdentity();

    /// <summary>When true, the <c>refresh_token</c> grant returns <c>invalid_grant</c> - used to
    /// exercise the refresh-fails-no-rotation path.</summary>
    public bool FailRefreshGrant { get; set; }

    /// <summary>
    /// <c>expires_in</c> (seconds) advertised on the initial <c>authorization_code</c> token
    /// response. Defaults to one hour. Set to a small value (e.g. 1) to make the cookie ticket's
    /// <c>expires_at</c> land inside Porta's refresh skew so the very next authenticated request
    /// triggers a proactive refresh. The <c>refresh_token</c> grant always issues a normal 3600s
    /// token, so a single refresh clears the near-expiry condition.
    /// </summary>
    public int InitialAccessTokenExpiresInSeconds { get; set; } = 3600;

    public FakeIdp(string authority = "https://idp.test")
    {
        Authority = authority;
        ClientId = "test-client";
        ClientSecret = "test-secret";

        using var rsa = RSA.Create(2048);
        _signingKey = new RsaSecurityKey(rsa.ExportParameters(true)) { KeyId = "fake-idp-key" };

        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services => services.AddRouting());
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/.well-known/openid-configuration", HandleDiscovery);
                        endpoints.MapGet("/.well-known/jwks", HandleJwks);
                        endpoints.MapGet("/authorize", HandleAuthorize);
                        endpoints.MapPost("/token", HandleToken);
                        endpoints.MapGet("/userinfo", HandleUserInfo);
                        endpoints.MapPost("/revoke", HandleRevocation);
                        endpoints.MapPost("/introspect", HandleIntrospection);
                        endpoints.MapGet("/end-session", HandleEndSession);
                    });
                });
            });

        _host = hostBuilder.Start();
        _testServer = _host.GetTestServer();
        _testServer.BaseAddress = new Uri(authority);
        BackchannelHandler = _testServer.CreateHandler();
        FrontchannelClient = _testServer.CreateClient();
        FrontchannelClient.BaseAddress = new Uri(authority);
    }

    public bool WasRevoked(string token)
    {
        lock (_revokedLock) return _revokedTokens.Contains(token);
    }

    /// <summary>Marks a token revoked out-of-band (mirroring an admin action or RFC 7009 revocation),
    /// without going through the HTTP <c>/revoke</c> endpoint. After this, the token introspects as
    /// <c>active=false</c>.</summary>
    public void Revoke(string token)
    {
        lock (_revokedLock) _revokedTokens.Add(token);
    }

    /// <summary>Total number of RFC 8693 token-exchange grants served.</summary>
    public int ExchangeCallCount => Volatile.Read(ref _exchangeCalls);

    /// <summary>Total number of <c>refresh_token</c> grants served.</summary>
    public int RefreshGrantCount => Volatile.Read(ref _refreshGrantCalls);

    /// <summary>Total number of RFC 7009 revocation calls served (counts every POST to <c>/revoke</c>,
    /// including duplicates) so tests can assert the IdP saw a revocation without knowing the token.</summary>
    public int RevocationCount => Volatile.Read(ref _revocationCalls);

    /// <summary>Number of token-exchange grants served for a specific audience.</summary>
    public int ExchangeCallCountFor(string audience)
        => _exchangeCallsByAudience.TryGetValue(audience, out var count) ? count : 0;

    /// <summary>Total number of RFC 7662 introspection calls served (every POST to <c>/introspect</c>),
    /// so tests can assert the BFF actually introspected rather than serving a cached result.</summary>
    public int IntrospectionCallCount => Volatile.Read(ref _introspectionCalls);

    /// <summary>
    /// Mints an opaque reference token (an RFC 6750 bearer string, not a JWT) and records the claims
    /// the introspection endpoint will report for it. Unlike JWTs, the token carries no embedded
    /// state - the SPA holds the opaque handle and Porta resolves it by POSTing to <c>/introspect</c>.
    /// Defaults bind the token to this IdP (<c>iss</c>=<see cref="Authority"/>), audience <c>"api"</c>,
    /// and <c>client_id</c>=<see cref="ClientId"/> so it satisfies Porta's default audience/issuer
    /// binding checks. A revoked token (see <c>/revoke</c>) or one past <paramref name="expiresAt"/>
    /// introspects as <c>active=false</c>.
    /// </summary>
    public string IssueReferenceToken(
        string sub = "user-1",
        string audience = "api",
        string? scope = "openid profile",
        DateTimeOffset? expiresAt = null)
    {
        var token = "ref-" + Guid.NewGuid().ToString("N");
        _referenceTokens[token] = new ReferenceTokenRecord(
            sub, audience, ClientId, scope, expiresAt ?? DateTimeOffset.UtcNow.AddHours(1));
        return token;
    }

    public void Dispose()
    {
        FrontchannelClient.Dispose();
        BackchannelHandler.Dispose();
        _testServer.Dispose();
        _host.Dispose();
    }

    private static ClaimsIdentity MakeDefaultIdentity()
    {
        var identity = new ClaimsIdentity(authenticationType: "fake-idp");
        identity.AddClaim(new Claim("sub", "user-1"));
        identity.AddClaim(new Claim("email", "user@example.com"));
        identity.AddClaim(new Claim("email_verified", "true", ClaimValueTypes.Boolean));
        identity.AddClaim(new Claim("name", "Test User"));
        identity.AddClaim(new Claim("preferred_username", "testuser"));
        return identity;
    }

    // ---- Endpoint handlers ----

    private Task HandleDiscovery(HttpContext context)
    {
        var doc = new
        {
            issuer = Authority,
            authorization_endpoint = $"{Authority}/authorize",
            token_endpoint = $"{Authority}/token",
            jwks_uri = $"{Authority}/.well-known/jwks",
            userinfo_endpoint = $"{Authority}/userinfo",
            revocation_endpoint = $"{Authority}/revoke",
            introspection_endpoint = $"{Authority}/introspect",
            end_session_endpoint = $"{Authority}/end-session",
            response_types_supported = new[] { "code" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            scopes_supported = new[] { "openid", "profile", "email" },
            grant_types_supported = new[] { "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange" },
        };
        return context.Response.WriteAsJsonAsync(doc);
    }

    private Task HandleJwks(HttpContext context)
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(_signingKey);
        return context.Response.WriteAsJsonAsync(new { keys = new[] { jwk } });
    }

    private async Task HandleAuthorize(HttpContext context)
    {
        var query = context.Request.Query;
        var redirectUri = query["redirect_uri"].ToString();
        var state = query["state"].ToString();
        var nonce = query["nonce"].ToString();
        var codeChallenge = query["code_challenge"].ToString();
        var codeChallengeMethod = query["code_challenge_method"].ToString();

        var code = Guid.NewGuid().ToString("N");
        _codes[code] = new IssuedCode(redirectUri, nonce, codeChallenge, codeChallengeMethod, NextUserIdentity);

        var separator = redirectUri.Contains('?') ? "&" : "?";
        var location = $"{redirectUri}{separator}code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(state)}";
        context.Response.Redirect(location);
        await Task.CompletedTask;
    }

    private async Task HandleToken(HttpContext context)
    {
        var form = await context.Request.ReadFormAsync();
        var grantType = form["grant_type"].ToString();

        if (grantType == "authorization_code")
        {
            var code = form["code"].ToString();
            var codeVerifier = form["code_verifier"].ToString();
            if (!_codes.TryRemove(code, out var issued))
            {
                await WriteOAuthError(context, "invalid_grant", "unknown code");
                return;
            }

            // PKCE check
            if (!string.IsNullOrEmpty(issued.CodeChallenge))
            {
                var verifierHash = Base64UrlEncode(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(codeVerifier)));
                if (verifierHash != issued.CodeChallenge)
                {
                    await WriteOAuthError(context, "invalid_grant", "PKCE mismatch");
                    return;
                }
            }

            var (accessToken, refreshToken, idToken) = IssueTokens(issued.UserIdentity, issued.Nonce);
            await context.Response.WriteAsJsonAsync(new
            {
                access_token = accessToken,
                refresh_token = refreshToken,
                id_token = idToken,
                token_type = "Bearer",
                expires_in = InitialAccessTokenExpiresInSeconds,
            });
            return;
        }

        if (grantType == "refresh_token")
        {
            Interlocked.Increment(ref _refreshGrantCalls);
            var refreshToken = form["refresh_token"].ToString();
            if (FailRefreshGrant || !_refreshTokens.TryGetValue(refreshToken, out var existing))
            {
                await WriteOAuthError(context, "invalid_grant", "unknown refresh_token");
                return;
            }

            // Rotate refresh token.
            _refreshTokens.TryRemove(refreshToken, out _);
            var (accessToken, newRefresh, idToken) = IssueTokens(existing.UserIdentity, nonce: null);
            await context.Response.WriteAsJsonAsync(new
            {
                access_token = accessToken,
                refresh_token = newRefresh,
                id_token = idToken,
                token_type = "Bearer",
                expires_in = 3600,
            });
            return;
        }

        if (grantType == "urn:ietf:params:oauth:grant-type:token-exchange")
        {
            var subjectToken = form["subject_token"].ToString();
            var audience = form["audience"].ToString();
            if (string.IsNullOrEmpty(subjectToken) || string.IsNullOrEmpty(audience))
            {
                await WriteOAuthError(context, "invalid_request", "subject_token and audience are required");
                return;
            }

            Interlocked.Increment(ref _exchangeCalls);
            _exchangeCallsByAudience.AddOrUpdate(audience, 1, (_, current) => current + 1);

            var exchangedToken = IssueExchangedAccessToken(audience);
            await context.Response.WriteAsJsonAsync(new
            {
                access_token = exchangedToken,
                issued_token_type = "urn:ietf:params:oauth:token-type:access_token",
                token_type = "Bearer",
                expires_in = 3600,
            });
            return;
        }

        await WriteOAuthError(context, "unsupported_grant_type", grantType);
    }

    private Task HandleUserInfo(HttpContext context)
    {
        var auth = context.Request.Headers.Authorization.ToString();
        if (!auth.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            context.Response.StatusCode = 401;
            return Task.CompletedTask;
        }
        return context.Response.WriteAsJsonAsync(new
        {
            sub = NextUserIdentity.FindFirst("sub")?.Value,
            email = NextUserIdentity.FindFirst("email")?.Value,
            name = NextUserIdentity.FindFirst("name")?.Value,
        });
    }

    private async Task HandleRevocation(HttpContext context)
    {
        Interlocked.Increment(ref _revocationCalls);
        var form = await context.Request.ReadFormAsync();
        var token = form["token"].ToString();
        lock (_revokedLock) _revokedTokens.Add(token);
        _refreshTokens.TryRemove(token, out _);
        context.Response.StatusCode = 200;
    }

    private async Task HandleIntrospection(HttpContext context)
    {
        Interlocked.Increment(ref _introspectionCalls);
        var form = await context.Request.ReadFormAsync();
        var token = form["token"].ToString();

        bool revoked;
        lock (_revokedLock) revoked = _revokedTokens.Contains(token);

        // RFC 7662 §2.2: an unknown, revoked, or expired token is reported as a single
        // {"active":false} object - the AS does not distinguish the reason to the caller.
        if (revoked
            || !_referenceTokens.TryGetValue(token, out var record)
            || record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            await context.Response.WriteAsJsonAsync(new { active = false });
            return;
        }

        await context.Response.WriteAsJsonAsync(new
        {
            active = true,
            sub = record.Sub,
            aud = record.Audience,
            client_id = record.ClientId,
            iss = Authority,
            scope = record.Scope,
            token_type = "Bearer",
            exp = record.ExpiresAt.ToUnixTimeSeconds(),
        });
    }

    private Task HandleEndSession(HttpContext context)
    {
        var redirect = context.Request.Query["post_logout_redirect_uri"].ToString();
        if (!string.IsNullOrEmpty(redirect))
        {
            context.Response.Redirect(redirect);
        }
        return Task.CompletedTask;
    }

    // ---- Helpers ----

    private (string AccessToken, string RefreshToken, string IdToken) IssueTokens(ClaimsIdentity identity, string? nonce)
    {
        var creds = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);
        var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var idTokenClaims = new List<Claim>(identity.Claims) { new("iat", iat, ClaimValueTypes.Integer64) };
        if (!string.IsNullOrEmpty(nonce))
        {
            idTokenClaims.Add(new Claim("nonce", nonce));
        }
        var idJwt = new JwtSecurityToken(
            issuer: Authority,
            audience: ClientId,
            claims: idTokenClaims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);
        var idToken = new JwtSecurityTokenHandler().WriteToken(idJwt);

        // A unique jti per issuance guarantees the access token string changes on every
        // refresh, so refresh-on-401 tests can observe the rotation even within the same second.
        var accessClaims = new List<Claim>(identity.Claims)
        {
            new("iat", iat, ClaimValueTypes.Integer64),
            new("jti", Guid.NewGuid().ToString("N")),
        };
        var accessJwt = new JwtSecurityToken(
            issuer: Authority,
            audience: "api",
            claims: accessClaims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);
        var accessToken = new JwtSecurityTokenHandler().WriteToken(accessJwt);

        var refreshToken = "rt-" + Guid.NewGuid().ToString("N");
        _refreshTokens[refreshToken] = new IssuedRefresh(identity);

        return (accessToken, refreshToken, idToken);
    }

    /// <summary>
    /// Mints an access token scoped to <paramref name="audience"/> for the RFC 8693 exchange grant.
    /// Carries a <c>purpose=token-exchange</c> claim and the requested audience so tests can confirm
    /// the backend received the exchanged token rather than the original session token.
    /// </summary>
    private string IssueExchangedAccessToken(string audience)
    {
        var creds = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);
        var claims = new List<Claim>
        {
            new("sub", NextUserIdentity.FindFirst("sub")?.Value ?? "user-1"),
            new("purpose", "token-exchange"),
            new("jti", Guid.NewGuid().ToString("N")),
        };
        var jwt = new JwtSecurityToken(
            issuer: Authority,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    /// <summary>
    /// Mints a spec-compliant OIDC back-channel <c>logout+jwt</c> signed with this IdP's key, so the
    /// BFF's back-channel logout endpoint accepts it (the signature validates against the published
    /// JWKS reached over the same backchannel handler). Defaults to terminating sessions for the
    /// default identity's subject (<c>user-1</c>) via the <c>sub</c> claim; pass <paramref name="sid"/>
    /// to target a specific session instead.
    /// </summary>
    public string CreateBackChannelLogoutToken(string sub = "user-1", string? sid = null, string? jti = null)
    {
        var creds = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);

        // OIDC Back-Channel Logout 1.0 §2.1: `events` is a JSON object whose single key is the
        // back-channel logout event type.
        var eventsValue = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["http://schemas.openid.net/event/backchannel-logout"] = new { },
        });

        var claims = new List<Claim>
        {
            new("events", eventsValue, JsonClaimValueTypes.Json),
            new("jti", jti ?? Guid.NewGuid().ToString("N")),
            new("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        };
        if (!string.IsNullOrEmpty(sub))
        {
            claims.Add(new Claim("sub", sub));
        }
        if (!string.IsNullOrEmpty(sid))
        {
            claims.Add(new Claim("sid", sid));
        }

        // §2.4: the JWT header `typ` MUST be `logout+jwt`. The JwtHeader ctor seeds `typ: JWT`; replace it.
        var header = new JwtHeader(creds);
        header.Remove("typ");
        header.Add("typ", "logout+jwt");

        var payload = new JwtPayload(
            issuer: Authority,
            audience: ClientId,
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(5));

        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }

    private static Task WriteOAuthError(HttpContext context, string error, string description)
    {
        context.Response.StatusCode = 400;
        return context.Response.WriteAsJsonAsync(new { error, error_description = description });
    }

    private static string Base64UrlEncode(byte[] data) => Convert.ToBase64String(data)
        .Replace("+", "-").Replace("/", "_").TrimEnd('=');

    private sealed record IssuedCode(string RedirectUri, string Nonce, string CodeChallenge, string CodeChallengeMethod, ClaimsIdentity UserIdentity);
    private sealed record IssuedRefresh(ClaimsIdentity UserIdentity);
    private sealed record ReferenceTokenRecord(string Sub, string Audience, string ClientId, string? Scope, DateTimeOffset ExpiresAt);
}
