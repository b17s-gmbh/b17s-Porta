using System.Diagnostics.Metrics;
using System.Globalization;
using System.Security.Claims;

using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace b17s.Porta.Tests.Auth.Tokens;

public class AccessTokenRefreshServiceTests
{
    [Fact]
    public async Task GetAccessTokenAsync_Unauthenticated_ReturnsNull()
    {
        using var ctx = new TestContext { Authenticated = false };

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Null(token);
    }

    [Fact]
    public async Task GetAccessTokenAsync_NotNearExpiry_ReturnsTokenWithoutRefresh()
    {
        using var ctx = new TestContext
        {
            AccessToken = "fresh-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30),
        };

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("fresh-access", token);
        Assert.Equal(0, ctx.RefreshCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_NearExpiry_RefreshesAndReturnsNewToken()
    {
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5), // within PortaCoreOptions.TokenRefreshSkew (60s default)
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = "new-rt",
                IdToken = "new-id",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", token);
        Assert.Equal(1, ctx.RefreshCalls);
        Assert.Equal(1, ctx.SignInCalls);
        Assert.Equal(1, ctx.ApiTokenInvalidationCalls);
        Assert.Equal("new-access", ctx.LastSignedInProperties?.GetTokenValue("access_token"));
        Assert.Equal("new-rt", ctx.LastSignedInProperties?.GetTokenValue("refresh_token"));
    }

    [Fact]
    public async Task GetAccessTokenAsync_NearExpiry_WithRotatedRefreshTokenAndSessionId_SyncsMetadata()
    {
        // Regression: after refresh-token rotation, AccessTokenRefreshService must
        // call ISessionManagementService.UpdateRefreshTokenAsync so admin and
        // back-channel revocation later target the *current* refresh token, not
        // the rotated-out one stored at registration time.
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "old-rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            SessionId = "sid-42",
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = "rotated-rt",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", token);
        var call = Assert.Single(ctx.Sessions.UpdateRefreshTokenCalls);
        Assert.Equal("sid-42", call.SessionId);
        Assert.Equal("ENC(rotated-rt)", call.EncryptedRefreshToken);
    }

    [Fact]
    public async Task GetAccessTokenAsync_RotationButNoSessionIdOnTicket_DoesNotSyncMetadata()
    {
        // Without a sessionId stashed on the ticket properties we have no key
        // to address the metadata record, so sync must not fire - better to
        // skip than to write under a guessed id.
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "old-rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            // SessionId left null.
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = "rotated-rt",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", token);
        Assert.Empty(ctx.Sessions.UpdateRefreshTokenCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_RotationWithoutNewRefreshToken_DoesNotSyncMetadata()
    {
        // If the IdP returns a refreshed access token but no new refresh token,
        // there's nothing to update - the registered refresh token is still
        // current.
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "old-rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            SessionId = "sid-42",
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = string.Empty, // simulate IdP not rotating
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", token);
        Assert.Empty(ctx.Sessions.UpdateRefreshTokenCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_NearExpiryButNoRefreshToken_ReturnsStaleAccessToken()
    {
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = null,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
        };

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("stale-access", token);
        Assert.Equal(0, ctx.RefreshCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_RefreshReturnsNull_FallsBackToOldAccessToken()
    {
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = null,
        };

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("stale-access", token);
        Assert.Equal(1, ctx.RefreshCalls);
        Assert.Equal(0, ctx.SignInCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_RefreshInvalidGrant_SignsOutAndReturnsNull()
    {
        // W3: a hard invalid_grant (refresh token revoked/expired/rotated-out at the IdP) must
        // NOT fall back to serving the stale access token - that would let a revoked session keep
        // working until the access token expires. Fail closed: sign out + drop API tokens + null.
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = null,
            RefreshFailure = RefreshFailureReason.InvalidGrant,
        };

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Null(token);
        Assert.Equal(1, ctx.RefreshCalls);
        Assert.Equal(0, ctx.SignInCalls);
        Assert.Equal(1, ctx.SignOutCalls);
        Assert.Equal(1, ctx.ApiTokenInvalidationCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_NearExpiry_ThreadsRequestAbortedToRefresh()
    {
        // W4: the request-driven refresh path must thread the inbound request's CancellationToken
        // (HttpContext.RequestAborted) into ITokenRefreshService.RefreshAsync so a hung IdP cannot
        // block the request past the refresh-lock TTL. Previously the parameterless overload was
        // used, discarding the token (-> CancellationToken.None).
        using var cts = new CancellationTokenSource();
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };
        ctx.HttpContext.RequestAborted = cts.Token;

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", token);
        Assert.Equal(1, ctx.RefreshCalls);
        Assert.Equal(cts.Token, ctx.LastRefreshCancellationToken);
    }

    [Fact]
    public async Task GetAccessTokenAsync_NoExpiresAt_DoesNotRefresh()
    {
        using var ctx = new TestContext
        {
            AccessToken = "no-expiry",
            RefreshToken = "rt",
            ExpiresAt = null,
        };

        var token = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("no-expiry", token);
        Assert.Equal(0, ctx.RefreshCalls);
    }

    /// <summary>
    /// Stitches together a fake <see cref="IAuthenticationService"/> with a
    /// pre-populated ticket plus stub refresh / api-token services. The system
    /// under test calls AuthenticateAsync/SignInAsync via the DI container.
    /// </summary>
    private sealed class TestContext : IDisposable
    {
        public bool Authenticated { get; init; } = true;
        public string? AccessToken { get; init; }
        public string? RefreshToken { get; init; }
        public string? IdToken { get; init; } = "id-1";
        public DateTimeOffset? ExpiresAt { get; init; }
        public string? SessionId { get; init; }
        public TokenExchangeResponse? RefreshResult { get; set; }

        // When RefreshResult is null, the kind of failure the stubbed refresh reports.
        public RefreshFailureReason RefreshFailure { get; init; } = RefreshFailureReason.Transient;

        public int RefreshCalls { get; private set; }
        public CancellationToken LastRefreshCancellationToken { get; private set; }
        public int SignInCalls { get; private set; }
        public int SignOutCalls { get; private set; }
        public int ApiTokenInvalidationCalls { get; private set; }
        public AuthenticationProperties? LastSignedInProperties { get; private set; }
        public StubSessionManagementService Sessions { get; }

        public AccessTokenRefreshService Service { get; }
        public HttpContext HttpContext { get; }

        public TestContext()
        {
            var fakeAuth = new FakeAuthenticationService(this);
            var refreshService = new StubTokenRefreshService(this);
            var apiTokenService = new StubApiTokenService(this);
            Sessions = new StubSessionManagementService();

            var services = new ServiceCollection();
            services.AddSingleton<IAuthenticationService>(fakeAuth);
            // The framework's AuthenticationHttpContextExtensions look up
            // IAuthenticationSchemeProvider as part of resolution; we provide
            // a no-op since the fake IAuthenticationService bypasses scheme lookup.
            services.AddSingleton<IAuthenticationSchemeProvider, NullSchemeProvider>();
            services.AddSingleton<IAuthenticationHandlerProvider, NullHandlerProvider>();
            HttpContext = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };

            var metrics = new PortaMetrics(new TestMeterFactory());
            LockRegistry = new RefreshLockRegistry(metrics);
            Service = new AccessTokenRefreshService(
                refreshService,
                apiTokenService,
                NullLogger<AccessTokenRefreshService>.Instance,
                LockRegistry,
                Microsoft.Extensions.Options.Options.Create(new PortaCoreOptions()),
                sessionManagement: Sessions);
        }

        public RefreshLockRegistry LockRegistry { get; }

        public void Dispose() => LockRegistry.Dispose();

        public AuthenticateResult BuildResult()
        {
            if (!Authenticated)
            {
                return AuthenticateResult.NoResult();
            }

            var identity = new ClaimsIdentity(authenticationType: CookieAuthenticationDefaults.AuthenticationScheme);
            identity.AddClaim(new Claim("sub", "user-1"));
            var principal = new ClaimsPrincipal(identity);
            var properties = new AuthenticationProperties();
            if (!string.IsNullOrEmpty(SessionId))
            {
                properties.Items[".bff.session_id"] = SessionId;
            }
            var tokens = new List<AuthenticationToken>();
            if (!string.IsNullOrEmpty(AccessToken)) tokens.Add(new AuthenticationToken { Name = "access_token", Value = AccessToken });
            if (!string.IsNullOrEmpty(RefreshToken)) tokens.Add(new AuthenticationToken { Name = "refresh_token", Value = RefreshToken });
            if (!string.IsNullOrEmpty(IdToken)) tokens.Add(new AuthenticationToken { Name = "id_token", Value = IdToken });
            if (ExpiresAt.HasValue) tokens.Add(new AuthenticationToken { Name = "expires_at", Value = ExpiresAt.Value.ToString("o", CultureInfo.InvariantCulture) });
            properties.StoreTokens(tokens);

            return AuthenticateResult.Success(new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme));
        }

        public void RecordRefresh(CancellationToken cancellationToken)
        {
            RefreshCalls++;
            LastRefreshCancellationToken = cancellationToken;
        }
        public void RecordSignOut() => SignOutCalls++;
        public void RecordApiTokenInvalidation() => ApiTokenInvalidationCalls++;
        public void RecordSignIn(AuthenticationProperties? properties)
        {
            SignInCalls++;
            LastSignedInProperties = properties;
        }

        private sealed class FakeAuthenticationService(TestContext ctx) : IAuthenticationService
        {
            public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
                => Task.FromResult(ctx.BuildResult());

            public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
                => Task.CompletedTask;

            public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
                => Task.CompletedTask;

            public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
            {
                ctx.RecordSignIn(properties);
                return Task.CompletedTask;
            }

            public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            {
                ctx.RecordSignOut();
                return Task.CompletedTask;
            }
        }

        private sealed class StubTokenRefreshService(TestContext ctx) : ITokenRefreshService
        {
            public Task<RefreshTokenResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
            {
                ctx.RecordRefresh(cancellationToken);
                var result = ctx.RefreshResult is { } response
                    ? RefreshTokenResult.Success(response)
                    : ctx.RefreshFailure == RefreshFailureReason.InvalidGrant
                        ? RefreshTokenResult.InvalidGrant()
                        : RefreshTokenResult.Transient();
                return Task.FromResult(result);
            }

            public Task<RefreshTokenResult> RefreshAsync(string refreshToken, TokenRefreshOptions options, CancellationToken cancellationToken = default)
                => RefreshAsync(refreshToken, cancellationToken);
        }

        public sealed class StubSessionManagementService : ISessionManagementService
        {
            public List<(string SessionId, string? EncryptedRefreshToken)> UpdateRefreshTokenCalls { get; } = new();

            public Task RegisterSessionAsync(string sessionId, string userId, string? email = null, string? ipAddress = null, string? userAgent = null, string? encryptedRefreshToken = null)
                => Task.CompletedTask;

            public Task UpdateRefreshTokenAsync(string sessionId, string? encryptedRefreshToken)
            {
                UpdateRefreshTokenCalls.Add((sessionId, encryptedRefreshToken));
                return Task.CompletedTask;
            }

            // Round-trip identity is fine for tests - we just need a non-null, deterministic
            // value so we can assert what got handed to UpdateRefreshTokenAsync.
            public string? ProtectRefreshToken(string? refreshToken)
                => string.IsNullOrEmpty(refreshToken) ? null : "ENC(" + refreshToken + ")";

            public Task<IReadOnlyList<SessionInfo>> GetSessionsByEmailAsync(string email, CancellationToken cancellationToken = default)
                => Task.FromResult<IReadOnlyList<SessionInfo>>(Array.Empty<SessionInfo>());

            public Task<bool> TerminateSessionAsync(string sessionId, bool revokeTokens = true, CancellationToken cancellationToken = default)
                => Task.FromResult(false);

            public Task<int> TerminateSessionsByEmailAsync(string email, bool revokeTokens = true, CancellationToken cancellationToken = default)
                => Task.FromResult(0);

            public Task<int> TerminateSessionsBySubjectAsync(string subject, bool revokeTokens = true, CancellationToken cancellationToken = default)
                => Task.FromResult(0);

            public Task TouchSessionAsync(string sessionId) => Task.CompletedTask;
        }

        private sealed class StubApiTokenService(TestContext ctx) : IApiTokenService
        {
            public Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, CancellationToken cancellationToken = default)
                => Task.FromResult<string?>(null);
            public Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default)
                => Task.FromResult<string?>(null);
            public Task InvalidateApiTokensAsync(HttpContext context, CancellationToken cancellationToken = default)
            {
                ctx.RecordApiTokenInvalidation();
                return Task.CompletedTask;
            }
            public Task InvalidateApiTokensAsync(HttpContext context, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default)
                => InvalidateApiTokensAsync(context, cancellationToken);
        }

        private sealed class NullSchemeProvider : IAuthenticationSchemeProvider
        {
            public Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
            public Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
            public Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
            public Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
            public Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
            public Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync() => Task.FromResult(Enumerable.Empty<AuthenticationScheme>());
            public Task<AuthenticationScheme?> GetSchemeAsync(string name) => Task.FromResult<AuthenticationScheme?>(null);
            public Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync() => Task.FromResult(Enumerable.Empty<AuthenticationScheme>());
            public void AddScheme(AuthenticationScheme scheme) { }
            public void RemoveScheme(string name) { }
        }

        private sealed class NullHandlerProvider : IAuthenticationHandlerProvider
        {
            public Task<IAuthenticationHandler?> GetHandlerAsync(HttpContext context, string authenticationScheme)
                => Task.FromResult<IAuthenticationHandler?>(null);
        }

        private sealed class TestMeterFactory : IMeterFactory
        {
            public Meter Create(MeterOptions options) => new(options);
            public void Dispose() { }
        }
    }
}
