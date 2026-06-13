using System.Net.Http.Json;
using System.Text;
using System.Xml.Serialization;

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

public sealed class BackendCallerContentTypeTests
{
    [Fact]
    public async Task ToBackend_WithXmlContentType_SerializesRequestAsXmlAndDeserializesXmlResponse()
    {
        // Regression for P1-3: ToBackend(method, url, contentType) used to store the
        // ContentType field but BackendCaller hard-coded JSON, ignoring it. The fix
        // plumbs RequestContentType through BackendRequest and uses IContentSerializer
        // for both request serialization and response deserialization.
        var capture = new RequestCaptureHandler(
            responseBody: "<EchoResponse><Echoed>ada</Echoed></EchoResponse>",
            responseContentType: ContentTypes.Xml);

        using var bff = await CreateBffAsync(capture, ContentType.Xml);
        var client = bff.GetTestServer().CreateClient();

        var payload = new EchoRequest { Name = "ada", Count = 7 };
        var response = await client.PostAsJsonAsync("/api/echo", payload, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();

        // Outgoing backend request was serialized as XML
        Assert.Equal(ContentTypes.Xml, capture.LastContentType);
        Assert.NotNull(capture.LastRequestBody);
        Assert.Contains("<EchoRequest", capture.LastRequestBody!);
        Assert.Contains("<Name>ada</Name>", capture.LastRequestBody);
        Assert.Contains("<Count>7</Count>", capture.LastRequestBody);

        // Backend XML response was deserialized and re-serialized as JSON to the client
        var clientPayload = await response.Content.ReadFromJsonAsync<EchoResponse>(TestContext.Current.CancellationToken);
        Assert.NotNull(clientPayload);
        Assert.Equal("ada", clientPayload!.Echoed);
    }

    [Fact]
    public async Task ToBackend_DefaultContentType_StillSerializesAsJson()
    {
        // Default behavior (no explicit content type) must remain JSON to preserve
        // backward compatibility for existing transformers.
        var capture = new RequestCaptureHandler(
            responseBody: "{\"echoed\":\"ada\"}",
            responseContentType: ContentTypes.Json);

        using var bff = await CreateBffAsync(capture, contentType: null);
        var client = bff.GetTestServer().CreateClient();

        var payload = new EchoRequest { Name = "ada", Count = 7 };
        var response = await client.PostAsJsonAsync("/api/echo", payload, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal(ContentTypes.Json, capture.LastContentType);
        Assert.NotNull(capture.LastRequestBody);
        Assert.Contains("\"name\":\"ada\"", capture.LastRequestBody);
    }

    private static async Task<IHost> CreateBffAsync(RequestCaptureHandler captureHandler, ContentType? contentType)
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
                    services.AddSingleton<EchoTransformer>();

                    // Replace the primary HTTP handler for the BackendCaller's named client
                    // so we can intercept outgoing requests without standing up a real server.
                    services.ConfigureHttpClientDefaults(b => { });
                    services.AddHttpClient(BackendCaller.HttpClientName)
                        .ConfigurePrimaryHttpMessageHandler(() => captureHandler);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        var builder = endpoints.MapTransformer<EchoTransformer, EchoRequest, EchoResponse>()
                            .FromPost("/api/echo");

                        builder = contentType.HasValue
                            ? builder.ToBackend("POST", "https://backend.test/echo", contentType.Value)
                            : builder.ToBackend("POST", "https://backend.test/echo");

                        builder.AllowAnonymous().Build();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    private sealed class EchoTransformer : ITransformer<EchoRequest, EchoResponse>
    {
        public async Task<EchoResponse> TransformAsync(EchoRequest? request, TransformerContext context)
        {
            var backendRequest = (BackendRequest)context.Properties["BackendRequest"];
            var result = await context.BackendCaller.CallAsync<EchoRequest, EchoResponse>(
                backendRequest,
                request!,
                context.CancellationToken);

            if (!result.IsSuccess)
            {
                throw new InvalidOperationException($"Backend failed: {result.Error}");
            }
            return result.Value!;
        }
    }

    [XmlRoot("EchoRequest")]
    public sealed class EchoRequest
    {
        public string Name { get; set; } = "";
        public int Count { get; set; }
    }

    [XmlRoot("EchoResponse")]
    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = "";
    }

    private sealed class RequestCaptureHandler : HttpMessageHandler
    {
        private readonly string _responseBody;
        private readonly string _responseContentType;

        public string? LastRequestBody { get; private set; }
        public string? LastContentType { get; private set; }

        public RequestCaptureHandler(string responseBody, string responseContentType)
        {
            _responseBody = responseBody;
            _responseContentType = responseContentType;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.Content != null)
            {
                LastRequestBody = await request.Content.ReadAsStringAsync(cancellationToken);
                LastContentType = request.Content.Headers.ContentType?.MediaType;
            }

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(_responseBody, Encoding.UTF8, _responseContentType)
            };
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
