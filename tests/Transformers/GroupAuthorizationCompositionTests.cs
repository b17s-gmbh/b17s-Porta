using System.Text.Encodings.Web;

using b17s.Porta.Configuration;
using b17s.Porta.Tests.Fixtures;

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

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Documents how a group-level <c>.RequireAuthorization()</c> interacts with Porta endpoints.
/// Porta owns authorization per endpoint: <c>Build()</c> always stamps explicit auth metadata
/// (<c>RequireAuthorization()</c> or <c>AllowAnonymous()</c>) based on the endpoint's effective
/// requirement, and an endpoint-level <c>AllowAnonymous()</c> overrides a group requirement. So a
/// group <c>.RequireAuthorization()</c> is NOT a reliable boundary for Porta endpoints.
/// </summary>
public sealed class GroupAuthorizationCompositionTests
{
    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = "";
    }

    // Control: a plain minimal-API endpoint DOES inherit the group requirement, so an anonymous
    // request is challenged (401). This is the behavior the doc example's comment implies.
    [Fact]
    public async Task GroupRequireAuthorization_AppliesToPlainEndpoint()
    {
        using var bff = await CreateBffAsync(
            new MockBackendCaller(),
            requireAuthByDefault: true,
            configureEndpoints: app =>
            {
                var catalog = app.MapGroup("/api/catalog").RequireAuthorization();
                catalog.MapGet("/plain", () => "plain");
            });

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/api/catalog/plain", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // A Porta endpoint that opts anonymous emits AllowAnonymous(), which overrides the group's
    // RequireAuthorization() — the endpoint is reachable without credentials.
    [Fact]
    public async Task PortaAllowAnonymous_OverridesGroupRequireAuthorization()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://products.internal/products", new EchoResponse { Echoed = "ok" });

        using var bff = await CreateBffAsync(
            backend,
            requireAuthByDefault: true,
            configureEndpoints: app =>
            {
                var catalog = app.MapGroup("/api/catalog").RequireAuthorization();
                catalog.MapPassThrough<EchoResponse>()
                    .FromGet("/products")
                    .ToBackend("GET", "https://products.internal/products")
                    .AllowAnonymous()
                    .Build();
            });

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/api/catalog/products", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // The silent footgun: with RequireAuthorizationByDefault = false, a Porta endpoint that never
    // calls .AllowAnonymous() STILL resolves to anonymous and stamps AllowAnonymous(), so the group
    // RequireAuthorization() is overridden even though nothing in the endpoint chain opted out.
    [Fact]
    public async Task PortaDefaultAnonymous_SilentlyOverridesGroupRequireAuthorization()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://products.internal/products", new EchoResponse { Echoed = "ok" });

        using var bff = await CreateBffAsync(
            backend,
            requireAuthByDefault: false,
            configureEndpoints: app =>
            {
                var catalog = app.MapGroup("/api/catalog").RequireAuthorization();
                catalog.MapPassThrough<EchoResponse>()
                    .FromGet("/products")
                    .ToBackend("GET", "https://products.internal/products")
                    .Build();   // no .AllowAnonymous(), no .RequireAuthorization()
            });

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/api/catalog/products", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task<IHost> CreateBffAsync(
        MockBackendCaller backend,
        bool requireAuthByDefault,
        Action<IEndpointRouteBuilder> configureEndpoints)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    // A scheme that never authenticates: an anonymous request hitting a
                    // RequireAuthorization endpoint is challenged -> 401.
                    services.AddAuthentication(NoAuthHandler.SchemeName)
                        .AddScheme<AuthenticationSchemeOptions, NoAuthHandler>(NoAuthHandler.SchemeName, _ => { });
                    services.AddAuthorization();
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<IBackendCaller>(backend);
                    services.AddTransient(typeof(BackendForwardingTransformer<>));
                    services.Configure<PortaCoreOptions>(o => o.RequireAuthorizationByDefault = requireAuthByDefault);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(configureEndpoints);
                });
            });
        return await hostBuilder.StartAsync();
    }

    private sealed class NoAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
    {
        public const string SchemeName = "NoAuth";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());
    }

    private sealed class AnonymousAuthProvider : IAuthenticationProvider
    {
        public Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(AuthenticationContext.Unauthenticated());

        public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
            => Task.FromResult<AuthenticationContext?>(null);

        public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
