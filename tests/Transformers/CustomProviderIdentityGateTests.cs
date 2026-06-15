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
/// Documents the interaction between ASP.NET's identity gate (<c>HttpContext.User</c>, enforced by
/// the <c>RequireAuthorization()</c> Porta stamps at <c>Build()</c>) and a Porta
/// <see cref="IAuthenticationProvider"/> that authenticates in-pipeline only.
///
/// A custom/header provider (and the built-in reference-token provider) populates the backend
/// <c>AuthContext</c> but does NOT set <c>HttpContext.User</c>. So with the default
/// <c>RequireAuthorizationByDefault = true</c>, the request is rejected at the identity gate BEFORE
/// the provider runs. The endpoint must opt out of the gate (<c>.AllowAnonymous()</c>) for the
/// provider to be reached.
/// </summary>
public sealed class CustomProviderIdentityGateTests
{
    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = "";
    }

    private const string ApiKeyHeader = "X-Api-Key";

    // Default RequireAuthorization: a valid API key is present, but because the custom provider does
    // not populate HttpContext.User, the identity gate short-circuits with 401 and the backend is
    // never called.
    [Fact]
    public async Task DefaultRequireAuthorization_ShortCircuitsBeforeCustomProvider()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://api.internal/data", new EchoResponse { Echoed = "ok" });

        using var bff = await CreateBffAsync(backend, requireAuthByDefault: true, app =>
            app.MapPassThrough<EchoResponse>()
                .FromGet("/api/data")
                .ToBackend("GET", "https://api.internal/data")
                .Build());

        var client = bff.GetTestServer().CreateClient();
        client.DefaultRequestHeaders.Add(ApiKeyHeader, "valid-key");
        var response = await client.GetAsync("/api/data", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(backend.RecordedCalls);   // provider never ran -> no backend call
    }

    // .AllowAnonymous() drops the identity gate, so the request reaches the handler, the custom
    // provider resolves the AuthContext from the API key, and the backend call goes out.
    [Fact]
    public async Task AllowAnonymous_LetsCustomProviderRun()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://api.internal/data", new EchoResponse { Echoed = "ok" });

        using var bff = await CreateBffAsync(backend, requireAuthByDefault: true, app =>
            app.MapPassThrough<EchoResponse>()
                .FromGet("/api/data")
                .ToBackend("GET", "https://api.internal/data")
                .AllowAnonymous()
                .Build());

        var client = bff.GetTestServer().CreateClient();
        client.DefaultRequestHeaders.Add(ApiKeyHeader, "valid-key");
        var response = await client.GetAsync("/api/data", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(backend.RecordedCalls);
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
                    services.AddAuthentication(NoAuthHandler.SchemeName)
                        .AddScheme<AuthenticationSchemeOptions, NoAuthHandler>(NoAuthHandler.SchemeName, _ => { });
                    services.AddAuthorization();
                    // A custom in-pipeline provider: authenticates from a header, never touches
                    // HttpContext.User. Mirrors ReferenceTokenAuthProvider / the ApiKey doc example.
                    services.AddSingleton<IAuthenticationProvider, ApiKeyHeaderProvider>();
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

    private sealed class ApiKeyHeaderProvider : IAuthenticationProvider
    {
        public Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
        {
            var key = context.Request.Headers[ApiKeyHeader].FirstOrDefault();
            if (string.IsNullOrEmpty(key))
            {
                return Task.FromResult(AuthenticationContext.Unauthenticated());
            }

            var ctx = new AuthenticationContext { AccessToken = key };
            ctx.Claims["sub"] = ["api-user"];
            return Task.FromResult(ctx);
        }

        public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
            => Task.FromResult<AuthenticationContext?>(null);

        public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default) => Task.CompletedTask;
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
}
