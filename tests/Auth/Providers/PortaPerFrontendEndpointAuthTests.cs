using System.Security.Claims;
using System.Text.Encodings.Web;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Services;
using b17s.Porta.Tests.Fixtures;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Auth.Providers;

/// <summary>
/// Proves Porta's auth composes with vanilla .NET authorization primitives: an <b>anonymous default</b>
/// (RequireAuthorizationByDefault = false) plus <b>per-endpoint, per-frontend</b> scheme selection via
/// named authorization policies that pin <c>AuthenticationSchemes</c> - all on Porta endpoints using the
/// standard <c>.RequireAuth("policy")</c> convention.
/// </summary>
public sealed class PortaPerFrontendEndpointAuthTests
{
    private const string ValidToken = "valid-opaque-token";

    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = "";
    }

    [Theory]
    // /public is anonymous by default (RequireAuthorizationByDefault = false) - no credential needed.
    [InlineData("/public", "none", null, HttpStatusCode.OK)]
    // /browser is pinned to the cookie scheme.
    [InlineData("/browser", "session", "bob", HttpStatusCode.OK)]
    [InlineData("/browser", "bearer", ValidToken, HttpStatusCode.Unauthorized)] // wrong frontend's credential
    [InlineData("/browser", "none", null, HttpStatusCode.Unauthorized)]
    // /api is pinned to the reference-token scheme.
    [InlineData("/api", "bearer", ValidToken, HttpStatusCode.OK)]
    [InlineData("/api", "session", "bob", HttpStatusCode.Unauthorized)]         // wrong frontend's credential
    [InlineData("/api", "none", null, HttpStatusCode.Unauthorized)]
    public async Task PerFrontendPolicies_PinEndpointsToTheirScheme(
        string path, string kind, string? credential, HttpStatusCode expected)
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://api.internal/public", new EchoResponse { Echoed = "public" })
            .SetupResponse("https://api.internal/browser", new EchoResponse { Echoed = "browser" })
            .SetupResponse("https://api.internal/api", new EchoResponse { Echoed = "api" });

        using var bff = await CreateBffAsync(backend);
        var client = bff.GetTestServer().CreateClient();

        if (kind == "session")
        {
            client.DefaultRequestHeaders.Add("X-Session", credential);
        }
        else if (kind == "bearer")
        {
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {credential}");
        }

        var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(expected, response.StatusCode);
    }

    private static async Task<IHost> CreateBffAsync(MockBackendCaller backend)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddDistributedMemoryCache();
                    services.AddSingleton<IReferenceTokenService>(new FakeIntrospector());

                    services.AddAuthentication()
                        .AddScheme<AuthenticationSchemeOptions, StubCookieHandler>("Cookies", _ => { });
                    services.AddPortaReferenceTokenScheme(options =>
                    {
                        options.Authority = "https://idp.test";
                        options.ValidateAudience = false;
                        options.ValidateIssuer = false;
                    });

                    // Per-frontend policies: each pins the schemes it will authenticate.
                    services.AddAuthorization(o =>
                    {
                        o.AddPolicy("browser", p => p
                            .RequireAuthenticatedUser()
                            .AddAuthenticationSchemes("Cookies"));
                        o.AddPolicy("api", p => p
                            .RequireAuthenticatedUser()
                            .AddAuthenticationSchemes(PortaReferenceTokenDefaults.AuthenticationScheme));
                    });

                    services.AddSingleton<IBackendCaller>(backend);
                    services.TryAddTransient(typeof(BackendForwardingTransformer<>));
                    services.TryAddScoped<IAuthenticationProvider>(sp =>
                        sp.GetRequiredService<ReferenceTokenAuthProvider>());
                    // Anonymous default: endpoints are public unless they opt in with .RequireAuth(policy).
                    services.Configure<PortaCoreOptions>(o => o.RequireAuthorizationByDefault = false);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapPassThrough<EchoResponse>()
                            .FromGet("/public")
                            .ToBackend("GET", "https://api.internal/public")
                            .Build();   // anonymous by default

                        endpoints.MapPassThrough<EchoResponse>()
                            .FromGet("/browser")
                            .ToBackend("GET", "https://api.internal/browser")
                            .RequireAuth("browser")
                            .Build();

                        endpoints.MapPassThrough<EchoResponse>()
                            .FromGet("/api")
                            .ToBackend("GET", "https://api.internal/api")
                            .RequireAuth("api")
                            .Build();
                    });
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
