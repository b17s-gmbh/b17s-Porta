using System.Security.Claims;
using System.Text.Json;

using b17s.Porta.Middleware;
using b17s.Porta.Tests.Fixtures;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Middleware;

/// <summary>
/// Tests for OidcLoginMiddleware. The middleware is now a thin shim over
/// <c>ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme)</c>; the bulk
/// of the test surface is the open-redirect guard on <c>redirect_uri</c> plus
/// the signed-return-URL policy that defends against attacker-crafted login
/// links pre-setting the post-login destination.
/// </summary>
public class OidcLoginMiddlewareTests
{
    [Theory]
    [InlineData("//evil.com")]
    [InlineData("//evil.com/path")]
    [InlineData("/\\evil.com")]
    [InlineData("/\\\\evil.com")]
    public async Task InvokeAsync_ProtocolRelativeOrBackslashRedirect_Returns400(string redirectUri)
    {
        var (middleware, httpContext, _) = CreateScenarioWithFakeAuth(
            redirectUri,
            new OidcLoginOptions { RequireSignedReturnUrl = false },
            authenticated: true);

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(400, httpContext.Response.StatusCode);
        Assert.Equal("Invalid redirect URI", ReadErrorBody(httpContext));
    }

    [Theory]
    [InlineData("/normal/path")]
    [InlineData("/")]
    public async Task InvokeAsync_SafeRelativeRedirect_FromAuthenticatedCaller_TriggersChallenge(string redirectUri)
    {
        var (middleware, httpContext, fakeAuth) = CreateScenarioWithFakeAuth(
            redirectUri,
            new OidcLoginOptions(),
            authenticated: true);

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(1, fakeAuth.ChallengeCalls);
        Assert.Equal("OpenIdConnect", fakeAuth.LastChallengeScheme);
        Assert.Equal(redirectUri, fakeAuth.LastChallengeProperties?.RedirectUri);
    }

    [Fact]
    public async Task InvokeAsync_RawRedirectUri_FromUnauthenticatedCaller_Returns400()
    {
        // B13 / P1-8: an attacker-crafted login link with a chosen redirect_uri
        // must not be honored for unauthenticated callers. We reject loudly with
        // 400 (and a pointer to the sign endpoint) rather than silently swapping
        // in DefaultRedirectUri - the silent fallback was a footgun that hid
        // misconfigured deep-links from frontend devs.
        var (middleware, httpContext, fakeAuth) = CreateScenarioWithFakeAuth(
            "/dashboard/admin",
            new OidcLoginOptions { RequireSignedReturnUrl = true, DefaultRedirectUri = "/" },
            authenticated: false);

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(400, httpContext.Response.StatusCode);
        Assert.Equal(0, fakeAuth.ChallengeCalls);

        httpContext.Response.Body.Position = 0;
        using var doc = JsonDocument.Parse(httpContext.Response.Body);
        Assert.Equal("redirect_uri must be signed", doc.RootElement.GetProperty("error").GetString());
        Assert.Equal("/bff/login/sign-return-url", doc.RootElement.GetProperty("sign_endpoint").GetString());
    }

    [Fact]
    public async Task InvokeAsync_RawRedirectUri_FromUnauthenticatedCaller_PermissiveMode_TriggersChallenge()
    {
        // Inverse of the above: when RequireSignedReturnUrl=false, an unauthenticated
        // caller's redirect_uri is honored as long as it passes the open-redirect guard.
        var (middleware, httpContext, fakeAuth) = CreateScenarioWithFakeAuth(
            "/dashboard",
            new OidcLoginOptions { RequireSignedReturnUrl = false },
            authenticated: false);

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(1, fakeAuth.ChallengeCalls);
        Assert.Equal("/dashboard", fakeAuth.LastChallengeProperties?.RedirectUri);
    }

    [Fact]
    public async Task InvokeAsync_SignedReturnUrl_FromUnauthenticatedCaller_IsHonored()
    {
        var protector = new ReturnUrlProtector(new EphemeralDataProtectionProvider(), NullLogger<ReturnUrlProtector>.Instance);
        var token = protector.Protect("/dashboard/admin", TimeSpan.FromMinutes(5));

        var (middleware, httpContext, fakeAuth) = CreateWithProtector(
            queryString: new Dictionary<string, string> { ["return_url"] = token },
            new OidcLoginOptions { RequireSignedReturnUrl = true },
            protector,
            authenticated: false);

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(1, fakeAuth.ChallengeCalls);
        Assert.Equal("/dashboard/admin", fakeAuth.LastChallengeProperties?.RedirectUri);
    }

    [Fact]
    public async Task InvokeAsync_TamperedReturnUrlToken_Returns400()
    {
        var protector = new ReturnUrlProtector(new EphemeralDataProtectionProvider(), NullLogger<ReturnUrlProtector>.Instance);

        var (middleware, httpContext, fakeAuth) = CreateWithProtector(
            queryString: new Dictionary<string, string> { ["return_url"] = "not-a-real-token" },
            new OidcLoginOptions(),
            protector,
            authenticated: false);

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(400, httpContext.Response.StatusCode);
        Assert.Equal(0, fakeAuth.ChallengeCalls);
        Assert.Equal("Invalid or expired return_url", ReadErrorBody(httpContext));
    }

    [Fact]
    public async Task InvokeAsync_ReturnUrlSignedByDifferentKey_Returns400()
    {
        var attackerProtector = new ReturnUrlProtector(new EphemeralDataProtectionProvider(), NullLogger<ReturnUrlProtector>.Instance);
        var serverProtector = new ReturnUrlProtector(new EphemeralDataProtectionProvider(), NullLogger<ReturnUrlProtector>.Instance);

        var forged = attackerProtector.Protect("/dashboard/admin", TimeSpan.FromMinutes(5));

        var (middleware, httpContext, fakeAuth) = CreateWithProtector(
            queryString: new Dictionary<string, string> { ["return_url"] = forged },
            new OidcLoginOptions(),
            serverProtector,
            authenticated: false);

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(400, httpContext.Response.StatusCode);
        Assert.Equal(0, fakeAuth.ChallengeCalls);
        Assert.Equal("Invalid or expired return_url", ReadErrorBody(httpContext));
    }

    [Fact]
    public async Task SignReturnUrlEndpoint_AnonymousCaller_Returns401()
    {
        var protector = new ReturnUrlProtector(new EphemeralDataProtectionProvider(), NullLogger<ReturnUrlProtector>.Instance);
        var (middleware, httpContext, _) = CreateWithProtector(
            queryString: new Dictionary<string, string> { ["redirect_uri"] = "/welcome" },
            new OidcLoginOptions(),
            protector,
            authenticated: false,
            path: "/bff/login/sign-return-url",
            method: "POST");

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(401, httpContext.Response.StatusCode);
        Assert.Equal("Authentication required", ReadErrorBody(httpContext));
    }

    [Fact]
    public async Task SignReturnUrlEndpoint_AuthenticatedCaller_ReturnsTokenThatTheLoginEndpointAccepts()
    {
        var protector = new ReturnUrlProtector(new EphemeralDataProtectionProvider(), NullLogger<ReturnUrlProtector>.Instance);

        var (signMiddleware, signContext, _) = CreateWithProtector(
            queryString: new Dictionary<string, string> { ["redirect_uri"] = "/welcome" },
            new OidcLoginOptions(),
            protector,
            authenticated: true,
            path: "/bff/login/sign-return-url",
            method: "POST");

        await signMiddleware.InvokeAsync(signContext);

        Assert.Equal(200, signContext.Response.StatusCode);
        signContext.Response.Body.Position = 0;
        using var doc = JsonDocument.Parse(signContext.Response.Body);
        var token = doc.RootElement.GetProperty("return_url").GetString();
        Assert.False(string.IsNullOrEmpty(token));

        var (loginMiddleware, loginContext, fakeAuth) = CreateWithProtector(
            queryString: new Dictionary<string, string> { ["return_url"] = token! },
            new OidcLoginOptions { RequireSignedReturnUrl = true },
            protector,
            authenticated: false);

        await loginMiddleware.InvokeAsync(loginContext);

        Assert.Equal(1, fakeAuth.ChallengeCalls);
        Assert.Equal("/welcome", fakeAuth.LastChallengeProperties?.RedirectUri);
    }

    // B7 regression: sign-return-url is auth-gated and CSRF-defended. A GET (or
    // any non-POST) carries the auth cookie under SameSite=Lax from a top-level
    // navigation or image tag, so it must not be reachable that way (the token
    // is not session-bound, so blocking unintended minting matters).
    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("DELETE")]
    [InlineData("PUT")]
    public async Task SignReturnUrlEndpoint_NonPostMethod_Returns405_BeforeAuthCheck(string method)
    {
        var protector = new ReturnUrlProtector(new EphemeralDataProtectionProvider(), NullLogger<ReturnUrlProtector>.Instance);
        var (middleware, httpContext, _) = CreateWithProtector(
            queryString: new Dictionary<string, string> { ["redirect_uri"] = "/welcome" },
            new OidcLoginOptions(),
            protector,
            authenticated: true,
            path: "/bff/login/sign-return-url",
            method: method);

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(405, httpContext.Response.StatusCode);
        Assert.Equal("POST", httpContext.Response.Headers.Allow.ToString());
        Assert.Equal("Method not allowed", ReadErrorBody(httpContext));
    }

    [Fact]
    public async Task InvokeAsync_NotMatchingPath_CallsNext()
    {
        var nextInvoked = false;
        var middleware = new OidcLoginMiddleware(
            _ => { nextInvoked = true; return Task.CompletedTask; },
            Options.Create(new OidcLoginOptions()),
            new ReturnUrlProtector(new EphemeralDataProtectionProvider(), NullLogger<ReturnUrlProtector>.Instance),
            NullLogger<OidcLoginMiddleware>.Instance,
            "/bff/login");
        var httpContext = TestFixtures.CreateHttpContext(path: "/somewhere/else");

        await middleware.InvokeAsync(httpContext);

        Assert.True(nextInvoked);
    }

    private static string ReadErrorBody(HttpContext context)
    {
        context.Response.Body.Position = 0;
        using var doc = JsonDocument.Parse(context.Response.Body);
        return doc.RootElement.GetProperty("error").GetString() ?? string.Empty;
    }

    private static (OidcLoginMiddleware middleware, HttpContext context, FakeAuthService fakeAuth) CreateScenarioWithFakeAuth(
        string redirectUri,
        OidcLoginOptions options,
        bool authenticated)
    {
        return CreateWithProtector(
            queryString: new Dictionary<string, string> { ["redirect_uri"] = redirectUri },
            options,
            new ReturnUrlProtector(new EphemeralDataProtectionProvider(), NullLogger<ReturnUrlProtector>.Instance),
            authenticated);
    }

    private static (OidcLoginMiddleware middleware, HttpContext context, FakeAuthService fakeAuth) CreateWithProtector(
        Dictionary<string, string> queryString,
        OidcLoginOptions options,
        IReturnUrlProtector protector,
        bool authenticated,
        string path = "/bff/login",
        string method = "GET")
    {
        var fakeAuth = new FakeAuthService();
        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService>(fakeAuth);

        var middleware = new OidcLoginMiddleware(
            _ => Task.CompletedTask,
            Options.Create(options),
            protector,
            NullLogger<OidcLoginMiddleware>.Instance,
            "/bff/login");

        var httpContext = TestFixtures.CreateHttpContext(
            method: method,
            path: path,
            queryString: queryString);
        httpContext.RequestServices = services.BuildServiceProvider();

        if (authenticated)
        {
            var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, "user-1")], "test");
            httpContext.User = new ClaimsPrincipal(identity);
        }

        return (middleware, httpContext, fakeAuth);
    }

    private sealed class FakeAuthService : IAuthenticationService
    {
        public int ChallengeCalls { get; private set; }
        public string? LastChallengeScheme { get; private set; }
        public AuthenticationProperties? LastChallengeProperties { get; private set; }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
            => Task.FromResult(AuthenticateResult.NoResult());

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            ChallengeCalls++;
            LastChallengeScheme = scheme;
            LastChallengeProperties = properties;
            return Task.CompletedTask;
        }

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }
}
