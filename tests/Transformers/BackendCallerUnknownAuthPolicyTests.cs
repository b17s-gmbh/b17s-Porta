using System.Net;
using System.Net.Http.Json;
using System.Text;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Configuration;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Regression tests for P0-4: an explicit but unknown <see cref="BackendRequest.BackendAuthPolicy"/>
/// must fail closed rather than silently downgrade to <see cref="BackendAuthPolicies.None"/>
/// (which previously caused user-supplied bearer tokens to be forwarded to a backend the
/// developer never authorized, bypassing TrustedHostValidator entirely).
/// </summary>
public sealed class BackendCallerUnknownAuthPolicyTests
{
    [Fact]
    public async Task ExplicitUnknownPolicy_FailsClosed_WithoutCallingBackend()
    {
        var capture = new RequestCaptureHandler(
            responseBody: "{\"echoed\":\"ada\"}",
            responseContentType: "application/json");

        using var bff = await CreateBffAsync(capture, "DefinitelyNotARegisteredPolicy");
        var client = bff.GetTestServer().CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/echo",
            new EchoRequest { Name = "ada" },
            TestContext.Current.CancellationToken);

        // The transformer surfaces backend failures as 502 by default; the important
        // assertion is that the call did NOT reach the backend.
        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(0, capture.CallCount);

        // A server-side misconfig (explicit policy that doesn't resolve) must classify as
        // ConfigurationError - not Unknown - so it isn't conflated with a user-credential
        // rejection and matches the adjacent BackendAuthConfigurationException path.
        var payload = await response.Content.ReadFromJsonAsync<ErrorPayload>(
            TestContext.Current.CancellationToken);
        Assert.Equal(nameof(BackendErrorType.ConfigurationError), payload?.ErrorType);
    }

    private sealed record ErrorPayload(string? Error, string? ErrorType);

    [Fact]
    public async Task NoExplicitPolicy_FallsBackToNone_AndCallsBackend()
    {
        // The fail-closed behavior is gated on `policyExplicit`. When no policy is set
        // on the BackendRequest, BackendCaller is allowed to use the implicit "None"
        // handler - verify we didn't accidentally over-tighten.
        var capture = new RequestCaptureHandler(
            responseBody: "{\"echoed\":\"ada\"}",
            responseContentType: "application/json");

        using var bff = await CreateBffAsync(capture, backendAuthPolicy: null);
        var client = bff.GetTestServer().CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/echo",
            new EchoRequest { Name = "ada" },
            TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal(1, capture.CallCount);
    }

    private static async Task<IHost> CreateBffAsync(RequestCaptureHandler captureHandler, string? backendAuthPolicy)
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
                    services.AddSingleton(new EchoTransformerOptions { BackendAuthPolicy = backendAuthPolicy });
                    services.AddSingleton<EchoTransformer>();

                    services.AddHttpClient(BackendCaller.HttpClientName)
                        .ConfigurePrimaryHttpMessageHandler(() => captureHandler);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapTransformer<EchoTransformer, EchoRequest, EchoResponse>()
                            .FromPost("/api/echo")
                            .ToBackend("POST", "https://backend.test/echo")
                            .AllowAnonymous()
                            .Build();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    private sealed class EchoTransformerOptions
    {
        public string? BackendAuthPolicy { get; init; }
    }

    private sealed class EchoTransformer(EchoTransformerOptions options) : ITransformer<EchoRequest, EchoResponse>
    {
        public async Task<EchoResponse> TransformAsync(EchoRequest? request, TransformerContext context)
        {
            // Override the backend auth policy from the registered options so each test
            // can assert behavior for a specific policy value (including "unknown").
            var fromBuilder = (BackendRequest)context.Properties["BackendRequest"];
            var backendRequest = fromBuilder with { BackendAuthPolicy = options.BackendAuthPolicy };

            var result = await context.BackendCaller.CallAsync<EchoRequest, EchoResponse>(
                backendRequest,
                request!,
                context.CancellationToken);

            if (!result.IsSuccess)
            {
                // Surface the failure type so the test can distinguish "unknown policy"
                // from a network or 5xx error.
                context.HttpContext.Response.StatusCode = StatusCodes.Status502BadGateway;
                await context.HttpContext.Response.WriteAsJsonAsync(
                    new { error = result.Error, errorType = result.ErrorType.ToString() });
                return new EchoResponse();
            }
            return result.Value!;
        }
    }

    public sealed class EchoRequest
    {
        public string Name { get; set; } = "";
    }

    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = "";
    }

    private sealed class RequestCaptureHandler : HttpMessageHandler
    {
        private readonly string _responseBody;
        private readonly string _responseContentType;

        public int CallCount { get; private set; }

        public RequestCaptureHandler(string responseBody, string responseContentType)
        {
            _responseBody = responseBody;
            _responseContentType = responseContentType;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_responseBody, Encoding.UTF8, _responseContentType)
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
