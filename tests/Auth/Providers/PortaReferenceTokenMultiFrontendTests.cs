using System.Security.Claims;
using System.Text.Encodings.Web;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Extensions;
using b17s.Porta.Services;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Auth.Providers;

/// <summary>
/// End-to-end multi-frontend proof: a single BFF that accepts browser callers (a cookie/session
/// scheme, kept as the default) AND opaque-token callers (the <c>PortaReferenceToken</c> scheme),
/// selected per request by a policy scheme / <c>ForwardDefaultSelector</c> - the exact pattern the
/// docs point to. Both credential types must authenticate the same <c>RequireAuthorization</c>
/// endpoint at runtime.
/// </summary>
public sealed class PortaReferenceTokenMultiFrontendTests
{
    private const string ValidToken = "valid-opaque-token";

    [Theory]
    [InlineData("session", "alice", null, HttpStatusCode.OK, "alice")]          // browser cookie -> Cookies scheme
    [InlineData("bearer", ValidToken, null, HttpStatusCode.OK, "user-42")]      // opaque token -> PortaReferenceToken scheme
    [InlineData("bearer", "revoked", null, HttpStatusCode.Unauthorized, null)]  // inactive opaque token
    [InlineData("none", null, null, HttpStatusCode.Unauthorized, null)]         // no credential
    public async Task SameEndpoint_AuthenticatesBothFrontends(
        string kind, string? credential, string? _, HttpStatusCode expected, string? expectedSub)
    {
        using var bff = await CreateBffAsync();
        var client = bff.GetTestServer().CreateClient();

        if (kind == "session")
        {
            client.DefaultRequestHeaders.Add("X-Session", credential);
        }
        else if (kind == "bearer")
        {
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {credential}");
        }

        var response = await client.GetAsync("/me", TestContext.Current.CancellationToken);

        Assert.Equal(expected, response.StatusCode);
        if (expected == HttpStatusCode.OK)
        {
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(expectedSub, body);
        }
    }

    private static async Task<IHost> CreateBffAsync()
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization();
                    services.AddDistributedMemoryCache();
                    services.AddSingleton<IReferenceTokenService>(new FakeIntrospector());

                    // "smart" virtual scheme is the default; it forwards per request to Cookies
                    // (browser) or the reference-token scheme (Authorization: Bearer ...).
                    services.AddAuthentication("smart")
                        .AddPolicyScheme("smart", "smart", o =>
                        {
                            o.ForwardDefaultSelector = ctx =>
                                ctx.Request.Headers.Authorization.Count > 0
                                    ? PortaReferenceTokenDefaults.AuthenticationScheme
                                    : "Cookies";
                        })
                        .AddScheme<AuthenticationSchemeOptions, StubCookieHandler>("Cookies", _ => { });

                    // Additive: must NOT steal the "smart" default.
                    services.AddPortaReferenceTokenScheme(options =>
                    {
                        options.Authority = "https://idp.test";
                        options.ValidateAudience = false;
                        options.ValidateIssuer = false;
                    });
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                        endpoints.MapGet("/me", (HttpContext ctx) => ctx.User.FindFirst("sub")?.Value ?? "")
                            .RequireAuthorization());
                });
            });
        return await hostBuilder.StartAsync();
    }

    private sealed class FakeIntrospector : IReferenceTokenService
    {
        public Task<ReferenceTokenIntrospectionResult?> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
            => Task.FromResult<ReferenceTokenIntrospectionResult?>(token == ValidToken
                ? new ReferenceTokenIntrospectionResult { IsActive = true, Claims = { ["sub"] = "user-42" } }
                : new ReferenceTokenIntrospectionResult { IsActive = false });
    }

    // Stands in for the cookie/OIDC session scheme: authenticates when an "X-Session" marker is present.
    private sealed class StubCookieHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var session = Request.Headers["X-Session"].FirstOrDefault();
            if (string.IsNullOrEmpty(session))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity("Cookies");
            identity.AddClaim(new Claim("sub", session));
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), "Cookies")));
        }
    }
}
