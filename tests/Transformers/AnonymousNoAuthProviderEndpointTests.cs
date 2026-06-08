using System.Net;
using System.Text;

using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Regression tests for the documented "Minimal Setup (No Auth)" path: an
/// <c>AddPortaCore</c>-only application with no authentication provider registered must be able
/// to serve anonymous transformer (pass-through) and raw-forward endpoints. The endpoint
/// handlers unconditionally resolve <c>IAuthenticationProvider</c>, so a registration factory
/// that threw on zero providers turned <c>.AllowAnonymous()</c> endpoints into a 500 at request
/// time instead of producing an unauthenticated context.
///
/// These hosts deliberately register NO auth provider, unlike the rest of the no-IdP test setups.
/// </summary>
public sealed class AnonymousNoAuthProviderEndpointTests
{
    public sealed class EchoResponse
    {
        public bool Ok { get; set; }
    }

    [Fact]
    public async Task AnonymousPassThrough_Succeeds_WithoutAuthProvider()
    {
        var capture = new OkBackendHandler();
        using var bff = await CreateBffAsync(capture, app => app.UseEndpoints(endpoints =>
            endpoints.MapPassThrough<EchoResponse>("GET", "/api/products")
                .ToBackend("GET", "https://backend.test/products")
                .AllowAnonymous()
                .Build()));

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/api/products", TestContext.Current.CancellationToken);

        // Before the fix: 500 (InvalidOperationException from the IAuthenticationProvider factory).
        response.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task AnonymousRawForward_Succeeds_WithoutAuthProvider()
    {
        var capture = new OkBackendHandler();
        using var bff = await CreateBffAsync(capture, app => app.UseEndpoints(endpoints =>
        {
            var builder = endpoints.MapRawForward<DefaultRawForwardTransformer>()
                .FromGet("/proxy/items")
                .ToBackend("GET", "https://backend.test/items")
                .AllowAnonymous();
            builder.Build();
        }));

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/proxy/items", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
    }

    private static async Task<IHost> CreateBffAsync(
        HttpMessageHandler backendHandler,
        Action<IApplicationBuilder> configure)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization();
                    // AddPortaCore ONLY - no AddPortaAuthentication / AddPortaOidcAuth / custom
                    // provider. This is the README "Minimal Setup (No Auth)" shape.
                    services.AddPortaCore();
                    services.AddScoped<DefaultRawForwardTransformer>();
                    services.AddHttpClient(BackendCaller.HttpClientName)
                        .ConfigurePrimaryHttpMessageHandler(() => backendHandler);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthorization();
                    configure(app);
                });
            });

        return await hostBuilder.StartAsync();
    }

    private sealed class OkBackendHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true}", Encoding.UTF8, "application/json"),
            });
    }
}
