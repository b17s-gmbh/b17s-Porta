using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Sessions;
using b17s.Porta.Configuration;
using b17s.Porta.Middleware;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace b17s.Porta.Tests.Middleware;

/// <summary>
/// Regression tests for P0-9: the back-channel logout endpoint must reject replayed
/// logout_tokens (same jti seen within token lifetime) and must reject tokens that
/// contain a <c>nonce</c> claim (OIDC §2.4 - logout_tokens MUST NOT carry one).
/// </summary>
public sealed class OidcBackChannelLogoutMiddlewareTests : IDisposable
{
    private const string Authority = "https://idp.test";
    private const string ClientId = "test-client";

    private readonly RSA _rsa;
    private readonly RsaSecurityKey _signingKey;
    private readonly StubDiscoveryService _discovery;
    private readonly RecordingSessionManagement _sessions;
    private readonly MemoryDistributedCache _replayCache;

    public OidcBackChannelLogoutMiddlewareTests()
    {
        _rsa = RSA.Create(2048);
        _signingKey = new RsaSecurityKey(_rsa.ExportParameters(true)) { KeyId = "bcl-key" };
        _discovery = new StubDiscoveryService(Authority, _signingKey);
        _sessions = new RecordingSessionManagement();
        _replayCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
    }

    public void Dispose() => _rsa.Dispose();

    [Fact]
    public async Task ReplayedJti_IsRejected()
    {
        var jti = Guid.NewGuid().ToString("N");
        var token = IssueLogoutToken(sub: "user-1", jti: jti);

        var first = await InvokeAsync(token);
        Assert.Equal(StatusCodes.Status200OK, first.Response.StatusCode);
        Assert.Equal(1, _sessions.TerminateBySubjectCallCount);

        // Same jti, second submission within the token's lifetime → reject.
        var second = await InvokeAsync(token);
        Assert.Equal(StatusCodes.Status400BadRequest, second.Response.StatusCode);
        // Crucially, the session-termination side-effect MUST NOT happen on a replay.
        Assert.Equal(1, _sessions.TerminateBySubjectCallCount);
    }

    [Fact]
    public async Task DifferentJti_SameSubject_IsAccepted()
    {
        // Sanity check: the cache must key on jti, not on sub. Two distinct logouts
        // for the same user (e.g. two devices) must both succeed.
        var first = IssueLogoutToken(sub: "user-1", jti: "jti-A");
        var second = IssueLogoutToken(sub: "user-1", jti: "jti-B");

        var r1 = await InvokeAsync(first);
        var r2 = await InvokeAsync(second);

        Assert.Equal(StatusCodes.Status200OK, r1.Response.StatusCode);
        Assert.Equal(StatusCodes.Status200OK, r2.Response.StatusCode);
        Assert.Equal(2, _sessions.TerminateBySubjectCallCount);
    }

    [Fact]
    public async Task TokenWithNonce_IsRejected()
    {
        // OIDC back-channel logout §2.4: a logout_token MUST NOT contain a nonce claim.
        // Presence of one means an id_token was confused with a logout_token.
        var token = IssueLogoutToken(sub: "user-1", jti: Guid.NewGuid().ToString("N"), extraClaims: [new Claim("nonce", "abc123")]);

        var response = await InvokeAsync(token);

        Assert.Equal(StatusCodes.Status400BadRequest, response.Response.StatusCode);
        Assert.Equal(0, _sessions.TerminateBySubjectCallCount);
    }

    [Fact]
    public async Task TokenMissingJti_IsRejected()
    {
        // Without a jti there's no way to enforce replay protection - the middleware
        // must require it rather than silently allow unbounded replays.
        var token = IssueLogoutToken(sub: "user-1", jti: null);

        var response = await InvokeAsync(token);

        Assert.Equal(StatusCodes.Status400BadRequest, response.Response.StatusCode);
        Assert.Equal(0, _sessions.TerminateBySubjectCallCount);
    }

    [Fact]
    public async Task TokenWithWrongTyp_IsRejected()
    {
        // OIDC back-channel logout §2.4: JWT header `typ` MUST be `logout+jwt`.
        // A signed id_token from the same IdP would carry `typ: JWT` and otherwise
        // pass signature/issuer/aud checks - the typ check is the primary defense.
        var token = IssueLogoutToken(sub: "user-1", jti: Guid.NewGuid().ToString("N"), typ: "JWT");

        var response = await InvokeAsync(token);

        Assert.Equal(StatusCodes.Status400BadRequest, response.Response.StatusCode);
        Assert.Equal(0, _sessions.TerminateBySubjectCallCount);
    }

    [Fact]
    public async Task TokenWithMissingTyp_IsRejected_WhenRequired()
    {
        // Default options require the typ header.
        var token = IssueLogoutToken(sub: "user-1", jti: Guid.NewGuid().ToString("N"), typ: null);

        var response = await InvokeAsync(token);

        Assert.Equal(StatusCodes.Status400BadRequest, response.Response.StatusCode);
        Assert.Equal(0, _sessions.TerminateBySubjectCallCount);
    }

    [Fact]
    public async Task TokenWithMissingTyp_IsAccepted_WhenLegacyOptOut()
    {
        // Operators with legacy IdPs can opt out of the typ check. The events-claim
        // backstop still runs - this test verifies the option actually loosens the gate.
        var token = IssueLogoutToken(sub: "user-1", jti: Guid.NewGuid().ToString("N"), typ: null);

        var response = await InvokeAsync(token, new OidcBackChannelLogoutOptions { RequireLogoutTypHeader = false });

        Assert.Equal(StatusCodes.Status200OK, response.Response.StatusCode);
        Assert.Equal(1, _sessions.TerminateBySubjectCallCount);
    }

    [Fact]
    public async Task UnsupportedContentType_IsRejected()
    {
        // Anonymous endpoint must reject non-form content types before touching the body.
        var context = await InvokeRawAsync(
            body: "{\"logout_token\":\"x\"}"u8.ToArray(),
            contentType: "application/json");

        Assert.Equal(StatusCodes.Status415UnsupportedMediaType, context.Response.StatusCode);
    }

    [Fact]
    public async Task MissingContentLength_IsRejected()
    {
        // Chunked uploads with no declared length can't be size-capped - reject upfront.
        var context = await InvokeRawAsync(
            body: "logout_token=x"u8.ToArray(),
            contentType: "application/x-www-form-urlencoded",
            includeContentLength: false);

        Assert.Equal(StatusCodes.Status411LengthRequired, context.Response.StatusCode);
    }

    [Fact]
    public async Task OversizedBody_IsRejected()
    {
        // The DoS defense: an attacker POSTing a multi-MB body must be cut off by
        // Content-Length check before ReadFormAsync allocates anything.
        var oversized = new byte[128 * 1024]; // 128 KB > default 64 KB cap
        Array.Fill(oversized, (byte)'a');

        var context = await InvokeRawAsync(
            body: oversized,
            contentType: "application/x-www-form-urlencoded");

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
    }

    [Fact]
    public async Task OversizedLogoutToken_IsRejected()
    {
        // Even within the body-size cap, an oversized token value should be rejected
        // before the JWT validator does any work.
        var hugeToken = new string('a', 32 * 1024); // > default 16 KB token cap
        var formBody = $"logout_token={hugeToken}";
        var bytes = Encoding.UTF8.GetBytes(formBody);

        // Bump the body cap so we exercise the per-token length check, not the body check.
        var context = await InvokeRawAsync(
            body: bytes,
            contentType: "application/x-www-form-urlencoded",
            options: new OidcBackChannelLogoutOptions { MaxRequestBodyBytes = 64 * 1024 });

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
    }

    private Task<HttpContext> InvokeAsync(string logoutToken) =>
        InvokeAsync(logoutToken, new OidcBackChannelLogoutOptions());

    private async Task<HttpContext> InvokeAsync(string logoutToken, OidcBackChannelLogoutOptions options)
    {
        var formBody = $"logout_token={Uri.EscapeDataString(logoutToken)}";
        var bytes = Encoding.UTF8.GetBytes(formBody);
        return await InvokeRawAsync(bytes, "application/x-www-form-urlencoded", includeContentLength: true, options: options);
    }

    private async Task<HttpContext> InvokeRawAsync(
        byte[] body,
        string contentType,
        bool includeContentLength = true,
        OidcBackChannelLogoutOptions? options = null)
    {
        var middleware = new OidcBackChannelLogoutMiddleware(
            next: _ => Task.CompletedTask,
            options: Options.Create(options ?? new OidcBackChannelLogoutOptions()),
            logger: NullLogger<OidcBackChannelLogoutMiddleware>.Instance);

        var services = new ServiceCollection()
            .AddSingleton<IDiscoveryService>(_discovery)
            .AddSingleton<ISessionManagementService>(_sessions)
            .AddSingleton<IDistributedCache>(_replayCache)
            .AddSingleton<IOptions<SessionAuthenticationConfiguration>>(
                Options.Create(new SessionAuthenticationConfiguration { Authority = Authority, ClientId = ClientId }))
            .BuildServiceProvider();

        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Method = "POST";
        context.Request.Path = "/bff/backchannel-logout";
        context.Request.ContentType = contentType;
        context.Request.Body = new MemoryStream(body);
        if (includeContentLength)
        {
            context.Request.ContentLength = body.Length;
        }
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(
            context,
            _discovery,
            _sessions,
            services.GetRequiredService<IOptions<SessionAuthenticationConfiguration>>(),
            _replayCache);

        return context;
    }

    private string IssueLogoutToken(string? sub, string? jti, IEnumerable<Claim>? extraClaims = null, string? typ = "logout+jwt")
    {
        var creds = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);

        // Per OIDC back-channel logout §2.1, the events claim is a JSON object whose
        // single key is the back-channel logout event type.
        var eventsValue = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["http://schemas.openid.net/event/backchannel-logout"] = new { },
        });

        var claims = new List<Claim>
        {
            new("events", eventsValue, JsonClaimValueTypes.Json),
            new("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        };
        if (!string.IsNullOrEmpty(sub))
        {
            claims.Add(new Claim("sub", sub));
        }
        if (!string.IsNullOrEmpty(jti))
        {
            claims.Add(new Claim("jti", jti));
        }
        if (extraClaims != null)
        {
            claims.AddRange(extraClaims);
        }

        // The JwtHeader ctor seeds a `typ: JWT` claim; overwrite it (or remove it)
        // so the test can simulate spec-compliant, legacy, and missing-typ tokens.
        var header = new JwtHeader(creds);
        header.Remove("typ");
        if (!string.IsNullOrEmpty(typ))
        {
            header.Add("typ", typ);
        }
        var payload = new JwtPayload(
            issuer: Authority,
            audience: ClientId,
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(5));

        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }

    private sealed class StubDiscoveryService : IDiscoveryService
    {
        private readonly OpenIdConnectConfiguration _config;

        public StubDiscoveryService(string authority, RsaSecurityKey signingKey)
        {
            _config = new OpenIdConnectConfiguration { Issuer = authority };
            _config.SigningKeys.Add(signingKey);
        }

        public Task<OpenIdConnectConfiguration?> GetConfigurationAsync(string authority, CancellationToken cancellationToken = default)
            => Task.FromResult<OpenIdConnectConfiguration?>(_config);
    }

    private sealed class RecordingSessionManagement : ISessionManagementService
    {
        public int TerminateBySubjectCallCount { get; private set; }
        public int TerminateBySessionIdCallCount { get; private set; }
        public string? LastReason { get; private set; }

        public Task<int> TerminateSessionsBySubjectAsync(string subject, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified")
        {
            TerminateBySubjectCallCount++;
            LastReason = reason;
            return Task.FromResult(1);
        }

        public Task<bool> TerminateSessionAsync(string sessionId, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified")
        {
            TerminateBySessionIdCallCount++;
            LastReason = reason;
            return Task.FromResult(true);
        }

        public Task RegisterSessionAsync(string sessionId, string userId, string? email = null, string? ipAddress = null, string? userAgent = null, string? encryptedRefreshToken = null) => Task.CompletedTask;
        public Task UpdateRefreshTokenAsync(string sessionId, string? encryptedRefreshToken) => Task.CompletedTask;
        public string? ProtectRefreshToken(string? refreshToken) => refreshToken;
        public Task<IReadOnlyList<SessionInfo>> GetSessionsByEmailAsync(string email, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<SessionInfo>>([]);
        public Task<int> TerminateSessionsByEmailAsync(string email, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified") => Task.FromResult(0);
        public Task TouchSessionAsync(string sessionId) => Task.CompletedTask;
    }
}
