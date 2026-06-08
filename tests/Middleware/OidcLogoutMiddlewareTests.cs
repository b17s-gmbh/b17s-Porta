using System.Security.Claims;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Tests.Fixtures;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Middleware;

public class OidcLogoutMiddlewareTests
{
    [Theory]
    [InlineData("//evil.com")]
    [InlineData("//evil.com/path")]
    [InlineData("/\\evil.com")]
    [InlineData("/\\\\evil.com")]
    public async Task InvokeAsync_ProtocolRelativeOrBackslashRedirect_Returns400(string redirectUri)
    {
        var (middleware, httpContext, _, revocation) = CreateScenario(redirectUri, authenticated: true, returnJson: true);

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.Equal(400, httpContext.Response.StatusCode);
        Assert.Equal(0, revocation.Calls);
    }

    [Theory]
    [InlineData("/normal/path")]
    [InlineData("/")]
    public async Task InvokeAsync_SafeRelativeRedirect_PassesValidation_AndSignsOutCookie(string redirectUri)
    {
        var (middleware, httpContext, fakeAuth, revocation) = CreateScenario(redirectUri, authenticated: true, returnJson: true);

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.NotEqual(400, httpContext.Response.StatusCode);
        Assert.True(fakeAuth.SignOutCalls > 0);
    }

    [Fact]
    public async Task InvokeAsync_Unauthenticated_Returns401()
    {
        var (middleware, httpContext, _, revocation) = CreateScenario("/", authenticated: false, returnJson: true);

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.Equal(401, httpContext.Response.StatusCode);
        Assert.Equal(0, revocation.Calls);
    }

    [Fact]
    public async Task InvokeAsync_GlobalLogout_RevokesRefreshTokenAndSignsOutBothSchemes()
    {
        var (middleware, httpContext, fakeAuth, revocation) = CreateScenario("/", authenticated: true, returnJson: false, performGlobalLogout: true);

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.Equal(1, revocation.Calls);
        Assert.Equal("rt-1", revocation.LastToken);
        Assert.Equal("refresh_token", revocation.LastHint);
        // SignOut called for both Cookie and OIDC schemes.
        Assert.Equal(2, fakeAuth.SignOutCalls);
    }

    [Fact]
    public async Task InvokeAsync_LocalLogout_DoesNotRevokeAtIdp()
    {
        var (middleware, httpContext, fakeAuth, revocation) = CreateScenario("/", authenticated: true, returnJson: false, performGlobalLogout: false);

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.Equal(0, revocation.Calls);
        // Only the cookie scheme is signed out; the OIDC handler is not invoked.
        Assert.Equal(1, fakeAuth.SignOutCalls);
    }

    [Fact]
    public async Task InvokeAsync_NotMatchingPath_CallsNext()
    {
        var nextInvoked = false;
        var middleware = new OidcLogoutMiddleware(
            _ => { nextInvoked = true; return Task.CompletedTask; },
            Options.Create(new OidcLogoutOptions()),
            NullLogger<OidcLogoutMiddleware>.Instance,
            "/bff/logout");
        var httpContext = TestFixtures.CreateHttpContext(path: "/somewhere/else");
        httpContext.RequestServices = new ServiceCollection().BuildServiceProvider();

        await middleware.InvokeAsync(httpContext, new RecordingRevocationService());

        Assert.True(nextInvoked);
    }

    // B7 regression: a GET (or any non-POST) on /bff/logout must not sign the
    // user out or revoke their refresh token. SameSite=Lax cookies attach on
    // top-level GET navigation, so accepting GET turns `<img src=…>` into a
    // CSRF logout + IdP-side token revocation primitive.
    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("DELETE")]
    [InlineData("PUT")]
    public async Task InvokeAsync_NonPostMethod_Returns405_AndDoesNotSignOutOrRevoke(string method)
    {
        var (middleware, httpContext, fakeAuth, revocation) = CreateScenario(
            "/", authenticated: true, returnJson: true, method: method);

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.Equal(405, httpContext.Response.StatusCode);
        Assert.Equal("POST", httpContext.Response.Headers.Allow.ToString());
        Assert.Equal(0, fakeAuth.SignOutCalls);
        Assert.Equal(0, revocation.Calls);
    }

    [Fact]
    public async Task InvokeAsync_Post_IsAccepted()
    {
        var (middleware, httpContext, fakeAuth, _) = CreateScenario(
            "/", authenticated: true, returnJson: true, method: "POST");

        await middleware.InvokeAsync(httpContext, new RecordingRevocationService());

        Assert.NotEqual(405, httpContext.Response.StatusCode);
        Assert.True(fakeAuth.SignOutCalls > 0);
    }

    // L10: defense-in-depth against future cookie-policy drift (e.g. SameSite=None).
    // With RequireAntiforgery=true and IAntiforgery not registered, the middleware
    // must fail closed rather than fall through to the auth check.
    [Fact]
    public async Task InvokeAsync_RequireAntiforgeryTrue_AntiforgeryServiceMissing_Returns403_AndDoesNotSignOut()
    {
        var fakeAuth = new FakeAuthService(authenticated: true, refreshToken: "rt-1");
        var revocation = new RecordingRevocationService();

        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService>(fakeAuth);

        var options = Options.Create(new OidcLogoutOptions
        {
            ReturnJson = true,
            PerformGlobalLogout = true,
            DefaultRedirectUri = "/",
            RequireAntiforgery = true,
        });
        var middleware = new OidcLogoutMiddleware(
            _ => Task.CompletedTask,
            options,
            NullLogger<OidcLogoutMiddleware>.Instance,
            "/bff/logout");

        var httpContext = TestFixtures.CreateHttpContext(method: "POST", path: "/bff/logout");
        httpContext.RequestServices = services.BuildServiceProvider();

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.Equal(403, httpContext.Response.StatusCode);
        Assert.Equal(0, fakeAuth.SignOutCalls);
        Assert.Equal(0, revocation.Calls);
    }

    [Fact]
    public async Task InvokeAsync_RequireAntiforgeryTrue_AntiforgeryValidates_Succeeds()
    {
        var fakeAuth = new FakeAuthService(authenticated: true, refreshToken: "rt-1");
        var revocation = new RecordingRevocationService();
        var antiforgery = new RecordingAntiforgery(succeed: true);

        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService>(fakeAuth);
        services.AddSingleton<IAntiforgery>(antiforgery);

        var options = Options.Create(new OidcLogoutOptions
        {
            ReturnJson = true,
            PerformGlobalLogout = true,
            DefaultRedirectUri = "/",
            RequireAntiforgery = true,
        });
        var middleware = new OidcLogoutMiddleware(
            _ => Task.CompletedTask,
            options,
            NullLogger<OidcLogoutMiddleware>.Instance,
            "/bff/logout");

        var httpContext = TestFixtures.CreateHttpContext(method: "POST", path: "/bff/logout");
        httpContext.RequestServices = services.BuildServiceProvider();

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.Equal(1, antiforgery.ValidateCalls);
        Assert.Equal(200, httpContext.Response.StatusCode);
        Assert.True(fakeAuth.SignOutCalls > 0);
    }

    [Fact]
    public async Task InvokeAsync_RequireAntiforgeryTrue_AntiforgeryRejects_Returns403_AndDoesNotSignOut()
    {
        var fakeAuth = new FakeAuthService(authenticated: true, refreshToken: "rt-1");
        var revocation = new RecordingRevocationService();
        var antiforgery = new RecordingAntiforgery(succeed: false);

        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService>(fakeAuth);
        services.AddSingleton<IAntiforgery>(antiforgery);

        var options = Options.Create(new OidcLogoutOptions
        {
            ReturnJson = true,
            PerformGlobalLogout = true,
            DefaultRedirectUri = "/",
            RequireAntiforgery = true,
        });
        var middleware = new OidcLogoutMiddleware(
            _ => Task.CompletedTask,
            options,
            NullLogger<OidcLogoutMiddleware>.Instance,
            "/bff/logout");

        var httpContext = TestFixtures.CreateHttpContext(method: "POST", path: "/bff/logout");
        httpContext.RequestServices = services.BuildServiceProvider();

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.Equal(403, httpContext.Response.StatusCode);
        Assert.Equal(0, fakeAuth.SignOutCalls);
        Assert.Equal(0, revocation.Calls);
    }

    [Fact]
    public async Task InvokeAsync_AntiforgeryRejects_RecordsCsrfValidationFailureMetric()
    {
        using var harness = b17s.Porta.Tests.Telemetry.RecordingMetricsHarness.Create();
        var fakeAuth = new FakeAuthService(authenticated: true, refreshToken: "rt-1");
        var revocation = new RecordingRevocationService();
        var antiforgery = new RecordingAntiforgery(succeed: false);

        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService>(fakeAuth);
        services.AddSingleton<IAntiforgery>(antiforgery);
        services.AddSingleton(harness.Metrics);

        var options = Options.Create(new OidcLogoutOptions
        {
            ReturnJson = true,
            PerformGlobalLogout = true,
            DefaultRedirectUri = "/",
            RequireAntiforgery = true,
        });
        var middleware = new OidcLogoutMiddleware(
            _ => Task.CompletedTask,
            options,
            NullLogger<OidcLogoutMiddleware>.Instance,
            "/bff/logout");

        var httpContext = TestFixtures.CreateHttpContext(method: "POST", path: "/bff/logout");
        httpContext.RequestServices = services.BuildServiceProvider();

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.Equal(403, httpContext.Response.StatusCode);
        var failures = harness.Drain("bff.csrf.validation_failures");
        Assert.Single(failures);
        Assert.Equal("oidc_logout", failures[0].Tags["reason"]);
    }

    [Fact]
    public async Task InvokeAsync_Logout_TerminatesServerSession_WithLogoutReason()
    {
        // The cookie sign-out clears the auth ticket, but the Porta session metadata + active gauge
        // are only torn down if logout also terminates the server-side session. Verify it does, with
        // revokeTokens=false (this middleware already performs RFC 7009 revocation itself).
        var fakeAuth = new FakeAuthService(authenticated: true, refreshToken: "rt-1");
        var revocation = new RecordingRevocationService();
        var sessions = new RecordingSessionManagement();

        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService>(fakeAuth);
        services.AddSingleton<b17s.Porta.Auth.Sessions.ISessionManagementService>(sessions);

        var options = Options.Create(new OidcLogoutOptions
        {
            ReturnJson = true,
            PerformGlobalLogout = false,
            DefaultRedirectUri = "/",
            RequireAntiforgery = false,
        });
        var middleware = new OidcLogoutMiddleware(
            _ => Task.CompletedTask,
            options,
            NullLogger<OidcLogoutMiddleware>.Instance,
            "/bff/logout");

        var httpContext = TestFixtures.CreateHttpContext(method: "POST", path: "/bff/logout");
        httpContext.RequestServices = services.BuildServiceProvider();

        await middleware.InvokeAsync(httpContext, revocation);

        Assert.Equal("sid-logout-test", sessions.LastTerminatedSessionId);
        Assert.Equal("logout", sessions.LastReason);
        Assert.False(sessions.LastRevokeTokens);
    }

    private sealed class RecordingSessionManagement : b17s.Porta.Auth.Sessions.ISessionManagementService
    {
        public string? LastTerminatedSessionId { get; private set; }
        public string? LastReason { get; private set; }
        public bool? LastRevokeTokens { get; private set; }

        public Task<bool> TerminateSessionAsync(string sessionId, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified")
        {
            LastTerminatedSessionId = sessionId;
            LastRevokeTokens = revokeTokens;
            LastReason = reason;
            return Task.FromResult(true);
        }

        public Task RegisterSessionAsync(string sessionId, string userId, string? email = null, string? ipAddress = null, string? userAgent = null, string? encryptedRefreshToken = null) => Task.CompletedTask;
        public Task UpdateRefreshTokenAsync(string sessionId, string? encryptedRefreshToken) => Task.CompletedTask;
        public string? ProtectRefreshToken(string? refreshToken) => refreshToken;
        public Task<IReadOnlyList<b17s.Porta.Auth.Sessions.SessionInfo>> GetSessionsByEmailAsync(string email, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<b17s.Porta.Auth.Sessions.SessionInfo>>([]);
        public Task<int> TerminateSessionsByEmailAsync(string email, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified") => Task.FromResult(0);
        public Task<int> TerminateSessionsBySubjectAsync(string subject, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified") => Task.FromResult(0);
        public Task TouchSessionAsync(string sessionId) => Task.CompletedTask;
    }

    private static (OidcLogoutMiddleware middleware, HttpContext context, FakeAuthService fakeAuth, RecordingRevocationService revocation) CreateScenario(
        string redirectUri,
        bool authenticated,
        bool returnJson,
        bool performGlobalLogout = true,
        string method = "POST")
    {
        var fakeAuth = new FakeAuthService(authenticated, refreshToken: "rt-1");
        var revocation = new RecordingRevocationService();

        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService>(fakeAuth);

        var options = Options.Create(new OidcLogoutOptions
        {
            ReturnJson = returnJson,
            PerformGlobalLogout = performGlobalLogout,
            DefaultRedirectUri = "/",
            // Antiforgery enforcement has its own dedicated tests; existing
            // scenarios exercise redirect / auth / method axes only.
            RequireAntiforgery = false,
        });
        var middleware = new OidcLogoutMiddleware(
            _ => Task.CompletedTask,
            options,
            NullLogger<OidcLogoutMiddleware>.Instance,
            "/bff/logout");

        var httpContext = TestFixtures.CreateHttpContext(
            method: method,
            path: "/bff/logout",
            queryString: new Dictionary<string, string> { ["redirect_uri"] = redirectUri });
        httpContext.RequestServices = services.BuildServiceProvider();

        return (middleware, httpContext, fakeAuth, revocation);
    }

    private sealed class FakeAuthService(bool authenticated, string? refreshToken) : IAuthenticationService
    {
        public int SignOutCalls { get; private set; }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        {
            if (!authenticated || scheme != CookieAuthenticationDefaults.AuthenticationScheme)
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity(authenticationType: scheme);
            var principal = new ClaimsPrincipal(identity);
            var properties = new AuthenticationProperties();
            properties.StoreTokens([new() { Name = "refresh_token", Value = refreshToken ?? "" }]);
            // Mirror the session-id the OIDC handler stamps onto the ticket at sign-in, so the
            // logout path can terminate the matching server-side session for gauge balance.
            properties.Items[".bff.session_id"] = "sid-logout-test";
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, properties, scheme)));
        }

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            SignOutCalls++;
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingAntiforgery(bool succeed) : IAntiforgery
    {
        public int ValidateCalls { get; private set; }

        public AntiforgeryTokenSet GetAndStoreTokens(HttpContext httpContext)
            => new("rt", "ct", "fn", "hn");
        public AntiforgeryTokenSet GetTokens(HttpContext httpContext)
            => new("rt", "ct", "fn", "hn");
        public Task<bool> IsRequestValidAsync(HttpContext httpContext)
            => Task.FromResult(succeed);
        public void SetCookieTokenAndHeader(HttpContext httpContext) { }
        public Task ValidateRequestAsync(HttpContext httpContext)
        {
            ValidateCalls++;
            return succeed
                ? Task.CompletedTask
                : throw new AntiforgeryValidationException("test: invalid token");
        }
    }

    private sealed class RecordingRevocationService : ITokenRevocationService
    {
        public int Calls { get; private set; }
        public string? LastToken { get; private set; }
        public string? LastHint { get; private set; }

        public Task<bool> RevokeTokenAsync(string token, TokenRevocationOptions options, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
            => Record(token, tokenTypeHint);
        public Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
            => Record(token, tokenTypeHint);
        public Task<TokenRevocationBatchResult> RevokeTokensAsync(TokenRevocationOptions options, CancellationToken cancellationToken, params (string Token, string? TokenTypeHint)[] tokens)
            => Task.FromResult(new TokenRevocationBatchResult { Outcomes = tokens.Select(t => new TokenRevocationOutcome(t.TokenTypeHint, true)).ToList() });
        public Task<TokenRevocationBatchResult> RevokeTokensAsync(CancellationToken cancellationToken, params (string Token, string? TokenTypeHint)[] tokens)
            => Task.FromResult(new TokenRevocationBatchResult { Outcomes = tokens.Select(t => new TokenRevocationOutcome(t.TokenTypeHint, true)).ToList() });

        private Task<bool> Record(string token, string? hint)
        {
            Calls++;
            LastToken = token;
            LastHint = hint;
            return Task.FromResult(true);
        }
    }
}
