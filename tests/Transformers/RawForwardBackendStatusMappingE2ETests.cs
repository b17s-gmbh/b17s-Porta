using System.Net;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Raw forward must give the same backend-error treatment as the typed routes: a *backend*
/// credential failure (401/403) means the BFF's credentials to the backend are wrong, NOT that the
/// user's session is invalid. Streaming a raw 401/403 to the frontend would trigger a sign-out.
/// These end-to-end <see cref="TestServer"/> tests drive the real <see cref="BackendCaller"/>
/// against a fake backend that returns specific status codes, asserting the
/// <see cref="IBackendErrorMapper"/> is applied on the response (success) path - not just the
/// transport-failure path.
/// </summary>
public sealed class RawForwardBackendStatusMappingE2ETests
{
    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task BackendAuthFailure_MappedTo502_AndBodyNotStreamed(HttpStatusCode backendStatus)
    {
        // The fake backend answers 401/403 with a tell-tale body. The default IBackendErrorMapper
        // remaps these to 502, so the client must see 502 and must NOT see the backend's body.
        using var bff = await CreateBffAsync(new FixedStatusBackendHandler(backendStatus, "BACKEND-AUTH-BODY"));
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/raw/thing", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("BACKEND-AUTH-BODY", body);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Conflict)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task BackendNonAuthError_StreamsThroughUnchanged(HttpStatusCode backendStatus)
    {
        // Raw forward is a proxy: non-auth backend errors (404/409/500/...) are legitimate to
        // relay verbatim - status and body - so the frontend can react to them.
        using var bff = await CreateBffAsync(new FixedStatusBackendHandler(backendStatus, "BACKEND-ERROR-BODY"));
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/raw/thing", TestContext.Current.CancellationToken);

        Assert.Equal(backendStatus, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("BACKEND-ERROR-BODY", body);
    }

    [Fact]
    public async Task BackendSuccess_StreamsThroughUnchanged()
    {
        using var bff = await CreateBffAsync(new FixedStatusBackendHandler(HttpStatusCode.OK, "OK-BODY"));
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/raw/thing", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("OK-BODY", body);
    }

    private static async Task<IHost> CreateBffAsync(HttpMessageHandler backendHandler)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddPortaCore(o => o.RequireAuthorizationByDefault = false);
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<PassThroughRawTransformer>();

                    // Point the BFF's outbound backend client at the fake backend handler.
                    services.AddHttpClient(BackendCaller.HttpClientName)
                        .ConfigurePrimaryHttpMessageHandler(() => backendHandler);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapRawForward<PassThroughRawTransformer>()
                            .FromGet("/raw/{*rest}")
                            .ToBackend("GET", "https://backend.test/data")
                            .AllowAnonymous()
                            .Build();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    private sealed class PassThroughRawTransformer : IRawTransformer
    {
    }

    /// <summary>Returns a fixed status code with a recognizable text body.</summary>
    private sealed class FixedStatusBackendHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body)
            });
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
