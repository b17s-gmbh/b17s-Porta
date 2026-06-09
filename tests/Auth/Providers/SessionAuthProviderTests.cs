using System.Security.Claims;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Auth.Providers;

public sealed class SessionAuthProviderTests
{
    [Fact]
    public async Task GetAuthContextAsync_NoAuthTicket_ReturnsUnauthenticated()
    {
        // Anonymous request: cookie scheme returns AuthenticateResult.NoResult().
        // No tokens, no claims, no refresh call.
        var refreshSvc = new RecordingRefresh();
        var apiTokens = new NoopApiTokenService();
        var fakeAuth = new FakeAuthenticationService(AuthenticateResult.NoResult());
        var http = BuildHttpContext(fakeAuth);
        var sut = new SessionAuthProvider(refreshSvc, new ThrowingTokenRefresh(), apiTokens, NullLogger<SessionAuthProvider>.Instance);

        var result = await sut.GetAuthContextAsync(http, TestContext.Current.CancellationToken);

        Assert.False(result.IsAuthenticated);
        Assert.Equal(0, refreshSvc.Calls);
    }

    [Fact]
    public async Task GetAuthContextAsync_AuthenticatedTicket_ProjectsClaimsAndTokens()
    {
        var refreshSvc = new RecordingRefresh { Token = "current-access-token" };
        var apiTokens = new NoopApiTokenService();

        var identity = new ClaimsIdentity("cookies");
        identity.AddClaim(new Claim("sub", "user-42"));
        identity.AddClaim(new Claim("email", "user@example.com"));
        var principal = new ClaimsPrincipal(identity);

        var properties = new AuthenticationProperties();
        properties.StoreTokens([
            new() { Name = "access_token", Value = "ticket-access-token" },
            new() { Name = "refresh_token", Value = "ticket-refresh-token" },
            new() { Name = "id_token", Value = "ticket-id-token" },
            new() { Name = "expires_at", Value = "2099-01-01T00:00:00Z" },
        ]);
        var ticket = new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme);

        var fakeAuth = new FakeAuthenticationService(AuthenticateResult.Success(ticket));
        var http = BuildHttpContext(fakeAuth);
        var sut = new SessionAuthProvider(refreshSvc, new ThrowingTokenRefresh(), apiTokens, NullLogger<SessionAuthProvider>.Instance);

        var result = await sut.GetAuthContextAsync(http, TestContext.Current.CancellationToken);

        Assert.True(result.IsAuthenticated);
        Assert.Equal("current-access-token", result.AccessToken); // from refresh service, not ticket
        Assert.Equal("ticket-refresh-token", result.RefreshToken);
        Assert.Equal("ticket-id-token", result.IdToken);
        Assert.NotNull(result.ExpiresAt);
        Assert.Equal("user-42", result.Claims["sub"][0]);
        Assert.Equal("user@example.com", result.Claims["email"][0]);
    }

    [Fact]
    public async Task GetAuthContextAsync_RefreshSessionTerminated_ReturnsUnauthenticated()
    {
        // invalid_grant fail-closed (report H2): AccessTokenRefreshService signed the dead
        // session out, but this request's cached auth ticket still carries the old access token.
        // The provider must NOT resurrect it via the ticket fallback - the request is
        // unauthenticated, full stop.
        var refreshSvc = new RecordingRefresh { SessionTerminated = true };
        var apiTokens = new NoopApiTokenService();

        var identity = new ClaimsIdentity("cookies");
        identity.AddClaim(new Claim("sub", "user-1"));
        var principal = new ClaimsPrincipal(identity);

        var properties = new AuthenticationProperties();
        properties.StoreTokens([
            new() { Name = "access_token", Value = "dead-session-access" },
            new() { Name = "refresh_token", Value = "rejected-refresh" },
        ]);
        var ticket = new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme);

        var fakeAuth = new FakeAuthenticationService(AuthenticateResult.Success(ticket));
        var http = BuildHttpContext(fakeAuth);
        var sut = new SessionAuthProvider(refreshSvc, new ThrowingTokenRefresh(), apiTokens, NullLogger<SessionAuthProvider>.Instance);

        var result = await sut.GetAuthContextAsync(http, TestContext.Current.CancellationToken);

        Assert.False(result.IsAuthenticated);
        Assert.Null(result.AccessToken);
        Assert.Null(result.RefreshToken);
        Assert.Empty(result.Claims);
    }

    [Fact]
    public async Task GetAuthContextAsync_RefreshReturnsNull_FallsBackToTicketAccessToken()
    {
        // When the refresh service yields no token (e.g. a custom IAccessTokenRefreshService
        // implementation that doesn't read the ticket), the provider uses the ticket's stored
        // access_token as a fallback. This only applies while the session is alive - the
        // terminated-session case above must short-circuit before this fallback.
        var refreshSvc = new RecordingRefresh { Token = null };
        var apiTokens = new NoopApiTokenService();

        var identity = new ClaimsIdentity("cookies");
        identity.AddClaim(new Claim("sub", "user-1"));
        var principal = new ClaimsPrincipal(identity);

        var properties = new AuthenticationProperties();
        properties.StoreTokens([
            new() { Name = "access_token", Value = "fallback-access" },
        ]);
        var ticket = new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme);

        var fakeAuth = new FakeAuthenticationService(AuthenticateResult.Success(ticket));
        var http = BuildHttpContext(fakeAuth);
        var sut = new SessionAuthProvider(refreshSvc, new ThrowingTokenRefresh(), apiTokens, NullLogger<SessionAuthProvider>.Instance);

        var result = await sut.GetAuthContextAsync(http, TestContext.Current.CancellationToken);

        Assert.Equal("fallback-access", result.AccessToken);
    }

    [Fact]
    public async Task GetAuthContextAsync_AccessTokenRefreshed_TriggersTicketReRead()
    {
        // The provider re-reads the cookie ticket after the refresh service runs, so the
        // returned context picks up rotated refresh/expires values, not the pre-refresh ones.
        var refreshSvc = new RecordingRefresh { Token = "rotated-access" };

        var initial = MakeTicket("user-1", refresh: "old-refresh", expiresAt: "2099-01-01T00:00:00Z");
        var rotated = MakeTicket("user-1", refresh: "rotated-refresh", expiresAt: "2099-06-01T00:00:00Z");

        var fakeAuth = new SequencedAuthenticationService(
            AuthenticateResult.Success(initial),
            AuthenticateResult.Success(rotated));
        var http = BuildHttpContext(fakeAuth);
        var sut = new SessionAuthProvider(refreshSvc, new ThrowingTokenRefresh(), new NoopApiTokenService(), NullLogger<SessionAuthProvider>.Instance);

        var result = await sut.GetAuthContextAsync(http, TestContext.Current.CancellationToken);

        Assert.Equal("rotated-refresh", result.RefreshToken);
        Assert.Equal(2, fakeAuth.Calls);
    }

    [Theory]
    [InlineData("2099-01-15T00:00:00Z", true)]
    [InlineData("1735689600", true)] // unix seconds form (2025-01-01)
    [InlineData("", false)]
    [InlineData("not-a-date", false)]
    public async Task GetAuthContextAsync_ParsesExpiresAt_FromIsoOrUnix(string raw, bool expectParsed)
    {
        // ExpiresAt comes off the ticket as either ISO-8601 (OIDC handler) or unix-seconds
        // (some custom flows). Anything else must yield null so callers don't treat garbage
        // as a far-future expiry.
        var refreshSvc = new RecordingRefresh { Token = null };
        var identity = new ClaimsIdentity("cookies");
        identity.AddClaim(new Claim("sub", "u"));
        var principal = new ClaimsPrincipal(identity);

        var properties = new AuthenticationProperties();
        properties.StoreTokens([new() { Name = "expires_at", Value = raw }]);

        var ticket = new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme);
        var fakeAuth = new FakeAuthenticationService(AuthenticateResult.Success(ticket));
        var http = BuildHttpContext(fakeAuth);
        var sut = new SessionAuthProvider(refreshSvc, new ThrowingTokenRefresh(), new NoopApiTokenService(), NullLogger<SessionAuthProvider>.Instance);

        var result = await sut.GetAuthContextAsync(http, TestContext.Current.CancellationToken);

        Assert.Equal(expectParsed, result.ExpiresAt.HasValue);
    }

    [Fact]
    public async Task RefreshAsync_NoRefreshToken_ReturnsNull_NoIdPCall()
    {
        // Bare context with no refresh token must short-circuit - calling the IdP without
        // a refresh token would result in an invalid_grant 400 and waste a round trip.
        var tokenRefresh = new RecordingTokenRefresh();
        var sut = new SessionAuthProvider(new ThrowingAccessTokenRefresh(), tokenRefresh, new NoopApiTokenService(), NullLogger<SessionAuthProvider>.Instance);

        var refreshed = await sut.RefreshAsync(new AuthenticationContext(), TestContext.Current.CancellationToken);

        Assert.Null(refreshed);
        Assert.Equal(0, tokenRefresh.Calls);
    }

    [Fact]
    public async Task RefreshAsync_ServiceReturnsNull_ReturnsNull()
    {
        var tokenRefresh = new RecordingTokenRefresh { Response = null };
        var sut = new SessionAuthProvider(new ThrowingAccessTokenRefresh(), tokenRefresh, new NoopApiTokenService(), NullLogger<SessionAuthProvider>.Instance);

        var refreshed = await sut.RefreshAsync(
            new AuthenticationContext { RefreshToken = "rt" },
            TestContext.Current.CancellationToken);

        Assert.Null(refreshed);
        Assert.Equal(1, tokenRefresh.Calls);
    }

    [Fact]
    public async Task RefreshAsync_SuccessfulResponse_RebuildsContextWithRotatedTokens()
    {
        var tokenRefresh = new RecordingTokenRefresh
        {
            Response = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = "new-refresh",
                IdToken = "new-id",
                ExpiresIn = 3600,
            },
        };
        var fakeClock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero));
        var sut = new SessionAuthProvider(
            new ThrowingAccessTokenRefresh(),
            tokenRefresh,
            new NoopApiTokenService(),
            NullLogger<SessionAuthProvider>.Instance,
            fakeClock);

        var current = new AuthenticationContext
        {
            RefreshToken = "rt",
            Claims = new Dictionary<string, string[]> { ["sub"] = ["user-9"] },
            Headers = new Dictionary<string, string> { ["X-Tenant"] = "acme" },
            ServiceTokens = new Dictionary<string, string> { ["orders"] = "tok-1" },
        };

        var refreshed = await sut.RefreshAsync(current, TestContext.Current.CancellationToken);

        Assert.NotNull(refreshed);
        Assert.Equal("new-access", refreshed!.AccessToken);
        Assert.Equal("new-refresh", refreshed.RefreshToken);
        Assert.Equal("new-id", refreshed.IdToken);
        Assert.Equal(new DateTimeOffset(2026, 5, 20, 13, 0, 0, TimeSpan.Zero), refreshed.ExpiresAt);
        Assert.Equal("user-9", refreshed.Claims["sub"][0]);
        Assert.Equal("acme", refreshed.Headers["X-Tenant"]);
        Assert.Equal("tok-1", refreshed.ServiceTokens["orders"]);

        // Mutating the returned context must NOT touch the input - the provider must
        // copy the dictionaries, not alias them.
        refreshed.Claims["sub"] = ["changed"];
        Assert.Equal("user-9", current.Claims["sub"][0]);
    }

    [Fact]
    public async Task RefreshAsync_ServiceThrows_SwallowsAndReturnsNull()
    {
        // Provider catches and logs; a transient IdP outage must not propagate as a 500.
        var tokenRefresh = new RecordingTokenRefresh { Throws = new HttpRequestException("idp down") };
        var sut = new SessionAuthProvider(new ThrowingAccessTokenRefresh(), tokenRefresh, new NoopApiTokenService(), NullLogger<SessionAuthProvider>.Instance);

        var refreshed = await sut.RefreshAsync(
            new AuthenticationContext { RefreshToken = "rt" },
            TestContext.Current.CancellationToken);

        Assert.Null(refreshed);
    }

    [Fact]
    public async Task InvalidateAsync_SignsOutAndInvalidatesApiTokens()
    {
        var apiTokens = new RecordingApiTokenService();
        var fakeAuth = new FakeAuthenticationService(AuthenticateResult.NoResult());
        var http = BuildHttpContext(fakeAuth);
        var sut = new SessionAuthProvider(new ThrowingAccessTokenRefresh(), new ThrowingTokenRefresh(), apiTokens, NullLogger<SessionAuthProvider>.Instance);

        await sut.InvalidateAsync(http, TestContext.Current.CancellationToken);

        Assert.Equal(CookieAuthenticationDefaults.AuthenticationScheme, fakeAuth.LastSignOutScheme);
        Assert.Equal(1, apiTokens.InvalidateCalls);
    }

    private static AuthenticationTicket MakeTicket(string sub, string? refresh = null, string? expiresAt = null)
    {
        var identity = new ClaimsIdentity("cookies");
        identity.AddClaim(new Claim("sub", sub));
        var principal = new ClaimsPrincipal(identity);
        var properties = new AuthenticationProperties();
        var tokens = new List<AuthenticationToken>();
        if (refresh is not null) tokens.Add(new AuthenticationToken { Name = "refresh_token", Value = refresh });
        if (expiresAt is not null) tokens.Add(new AuthenticationToken { Name = "expires_at", Value = expiresAt });
        if (tokens.Count > 0) properties.StoreTokens(tokens);
        return new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme);
    }

    private static HttpContext BuildHttpContext(IAuthenticationService authService)
    {
        var services = new ServiceCollection();
        services.AddSingleton(authService);
        var http = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        return http;
    }

    private sealed class FakeAuthenticationService(AuthenticateResult result) : IAuthenticationService
    {
        public string? LastSignOutScheme { get; private set; }
        public int Calls { get; private set; }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        {
            Calls++;
            return Task.FromResult(result);
        }

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, System.Security.Claims.ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            LastSignOutScheme = scheme;
            return Task.CompletedTask;
        }
    }

    private sealed class SequencedAuthenticationService : IAuthenticationService
    {
        private readonly Queue<AuthenticateResult> _results;
        public int Calls { get; private set; }

        public SequencedAuthenticationService(params AuthenticateResult[] results)
        {
            _results = new Queue<AuthenticateResult>(results);
        }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        {
            Calls++;
            return Task.FromResult(_results.Dequeue());
        }

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }

    private sealed class RecordingRefresh : IAccessTokenRefreshService
    {
        public string? Token { get; set; } = "access";
        public bool SessionTerminated { get; set; }
        public int Calls { get; private set; }

        public Task<AccessTokenResult> GetAccessTokenAsync(HttpContext context)
        {
            Calls++;
            return Task.FromResult(SessionTerminated ? AccessTokenResult.SignedOut() : AccessTokenResult.FromToken(Token));
        }

        public Task<string?> ForceRefreshAsync(HttpContext context, string? staleAccessToken = null)
        {
            Calls++;
            return Task.FromResult(Token);
        }
    }

    private sealed class ThrowingAccessTokenRefresh : IAccessTokenRefreshService
    {
        public Task<AccessTokenResult> GetAccessTokenAsync(HttpContext context) => throw new InvalidOperationException("must not be called");
        public Task<string?> ForceRefreshAsync(HttpContext context, string? staleAccessToken = null) => throw new InvalidOperationException("must not be called");
    }

    private sealed class RecordingTokenRefresh : ITokenRefreshService
    {
        public int Calls { get; private set; }
        public TokenExchangeResponse? Response { get; set; }
        public Exception? Throws { get; set; }

        public Task<RefreshTokenResult> RefreshAsync(string refreshToken, TokenRefreshOptions options, CancellationToken cancellationToken = default)
        {
            Calls++;
            if (Throws is not null) throw Throws;
            return Task.FromResult(Response is { } r ? RefreshTokenResult.Success(r) : RefreshTokenResult.Transient());
        }

        public Task<RefreshTokenResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            Calls++;
            if (Throws is not null) throw Throws;
            return Task.FromResult(Response is { } r ? RefreshTokenResult.Success(r) : RefreshTokenResult.Transient());
        }
    }

    private sealed class ThrowingTokenRefresh : ITokenRefreshService
    {
        public Task<RefreshTokenResult> RefreshAsync(string refreshToken, TokenRefreshOptions options, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("must not be called");

        public Task<RefreshTokenResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("must not be called");
    }

    private sealed class NoopApiTokenService : IApiTokenService
    {
        public Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, CancellationToken cancellationToken = default)
            => Task.FromResult<string?>(null);

        public Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default)
            => Task.FromResult<string?>(null);

        public Task InvalidateApiTokensAsync(HttpContext context, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task InvalidateApiTokensAsync(HttpContext context, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }

    private sealed class RecordingApiTokenService : IApiTokenService
    {
        public int InvalidateCalls { get; private set; }

        public Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, CancellationToken cancellationToken = default)
            => Task.FromResult<string?>(null);

        public Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default)
            => Task.FromResult<string?>(null);

        public Task InvalidateApiTokensAsync(HttpContext context, CancellationToken cancellationToken = default)
        {
            InvalidateCalls++;
            return Task.CompletedTask;
        }

        public Task InvalidateApiTokensAsync(HttpContext context, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default)
        {
            InvalidateCalls++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
