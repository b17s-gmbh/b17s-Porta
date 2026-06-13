using System.Net;
using System.Net.Http.Json;
using System.Text;

using b17s.Porta.Auth.Providers;
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
/// Regression tests for M1: an auth-handler exception on a <c>MapPassThrough</c> endpoint
/// (e.g. a token exchange failure) previously surfaced as a 401 with the internal exception
/// message written verbatim to the client - bypassing <see cref="IBackendErrorMapper"/>, which
/// only saw real backend HTTP responses. That is exactly the "BFF credential failure signs the
/// user out" failure mode the default 401 -&gt; 502 mapping exists to prevent. The synthetic
/// failure must now run through the mapper like a real backend 401 and carry a generic message.
/// </summary>
public sealed class PassThroughAuthFailureMappingTests
{
    [Fact]
    public async Task PassThrough_AuthHandlerThrows_Returns502_WithGenericError()
    {
        var capture = new RequestCaptureHandler();

        using var bff = await CreateBffAsync(capture);
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/api/echo", TestContext.Current.CancellationToken);

        // Mapped by the default IBackendErrorMapper: NOT a 401, so the frontend never
        // interprets a BFF backend-credential problem as the user's session expiring.
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Equal(0, capture.CallCount); // the backend was never called

        var payload = await response.Content.ReadFromJsonAsync<ErrorPayload>(
            TestContext.Current.CancellationToken);
        // Generic mapper message only - the auth handler's exception message stays in the logs.
        Assert.Equal("Backend service authentication failed", payload?.Error);
        Assert.DoesNotContain("token endpoint exploded", payload?.Error);
    }

    private sealed record ErrorPayload(string? Error);

    private static async Task<IHost> CreateBffAsync(RequestCaptureHandler captureHandler)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddPortaCore();
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<IBackendAuthHandler>(new ThrowingAuthHandler("Throwing"));

                    services.AddHttpClient(BackendCaller.HttpClientName)
                        .ConfigurePrimaryHttpMessageHandler(() => captureHandler);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapPassThrough<EchoResponse>()
                            .FromGet("/api/echo")
                            .ToBackend("GET", "https://backend.test/echo")
                            .WithBackendAuth("Throwing")
                            .AllowAnonymous()
                            .Build();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = "";
    }

    private sealed class ThrowingAuthHandler(string policy) : IBackendAuthHandler
    {
        public string PolicyName { get; } = policy;
        public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
            => throw new InvalidOperationException("token endpoint exploded");
    }

    private sealed class RequestCaptureHandler : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"echoed\":\"ok\"}", Encoding.UTF8, "application/json")
            });
        }
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
