using System.Net.Http.Json;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Tests.Fixtures;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Transformers;

public sealed class TransformerEndpointBuilderFromAnyTests
{
    [Fact]
    public async Task FromAny_PostWithJsonBody_DeserializesIntoTypedRequest()
    {
        // Regression for P0-2: the body-deserialization gate compared the captured
        // _httpMethod ("*" for FromAny) against POST/PUT/PATCH and short-circuited,
        // so typed-request transformers mounted under FromAny() received default(TRequest)
        // for real POST bodies. The fix compares against context.Request.Method.
        var transformer = new RecordingTransformer();
        using var bff = await CreateBffAsync(transformer);
        var client = bff.GetTestServer().CreateClient();

        var payload = new EchoRequest { Name = "ada", Count = 7 };
        var response = await client.PostAsJsonAsync("/proxy/widgets/42", payload, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.NotNull(transformer.LastRequest);
        Assert.Equal("ada", transformer.LastRequest!.Name);
        Assert.Equal(7, transformer.LastRequest.Count);
    }

    [Fact]
    public async Task FromAny_GetRequest_DoesNotAttemptDeserialization()
    {
        // GETs have no JSON body; the gate must skip deserialization. ReadFromJsonAsync
        // on an empty body would throw JsonException and the handler would 400.
        var transformer = new RecordingTransformer();
        using var bff = await CreateBffAsync(transformer);
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/proxy/widgets/42", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Null(transformer.LastRequest);
    }

    private static async Task<IHost> CreateBffAsync(RecordingTransformer transformer)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<IBackendCaller>(new MockBackendCaller());
                    services.AddSingleton(transformer);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapTransformer<RecordingTransformer, EchoRequest, EchoResponse>()
                            .FromAny("/proxy/{**path}")
                            .ToBackend("POST", "https://backend.test/{**path}")
                            .AllowAnonymous()
                            .Build();
                    });
                });
            });

        var host = await hostBuilder.StartAsync();
        return host;
    }

    private sealed class RecordingTransformer : ITransformer<EchoRequest, EchoResponse>
    {
        public EchoRequest? LastRequest { get; private set; }

        public Task<EchoResponse> TransformAsync(EchoRequest? request, TransformerContext context)
        {
            LastRequest = request;
            return Task.FromResult(new EchoResponse { Echoed = request?.Name ?? "<null>" });
        }
    }

    public sealed class EchoRequest
    {
        public string Name { get; set; } = "";
        public int Count { get; set; }
    }

    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = "";
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
