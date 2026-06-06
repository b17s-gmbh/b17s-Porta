using System.Net;
using System.Net.Http.Headers;
using System.Text;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Tests.Fixtures;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Regression tests for P0-3: backend response headers like Set-Cookie and the
/// ModifyResponseHeaders hook were leaking / no-op'ing through raw-forward.
/// </summary>
public sealed class RawForwardResponseHeadersTests
{
    [Fact]
    public async Task SetCookie_FromBackend_IsStrippedByDefault()
    {
        // Backend plants a cookie. Without an opt-in, it must not reach the client -
        // otherwise a backend can shadow the BFF session cookie.
        using var bff = await CreateBffAsync(builder => builder
            .FromGet("/proxy/files/{id}")
            .ToBackend("GET", "https://backend.test/files/{id}")
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/proxy/files/42", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.False(
            response.Headers.Contains("Set-Cookie"),
            "Set-Cookie from backend must not leak to the client without an explicit opt-in");
    }

    [Fact]
    public async Task SetCookie_FromBackend_ForwardsWhenAllowed()
    {
        using var bff = await CreateBffAsync(builder => builder
            .FromGet("/proxy/files/{id}")
            .ToBackend("GET", "https://backend.test/files/{id}")
            .AllowForwardingResponseHeaders(["Set-Cookie"])
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/proxy/files/42", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.True(
            response.Headers.Contains("Set-Cookie"),
            "Set-Cookie should pass through when added to AllowedResponseHeaders");
    }

    [Fact]
    public async Task SensitivePolicyHeaders_FromBackend_AreStrippedByDefault()
    {
        using var bff = await CreateBffAsync(builder => builder
            .FromGet("/proxy/files/{id}")
            .ToBackend("GET", "https://backend.test/files/{id}")
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/proxy/files/42", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        // The fake backend always sends these - verify the BFF strips them.
        Assert.False(response.Headers.Contains("Strict-Transport-Security"));
        Assert.False(response.Headers.Contains("Content-Security-Policy"));
        Assert.False(response.Headers.Contains("Server"));
        Assert.False(response.Headers.Contains("X-Powered-By"));
    }

    [Fact]
    public async Task ContentType_FromBackend_PassesThrough()
    {
        // Sanity check: the new filter must not strip ordinary content headers.
        using var bff = await CreateBffAsync(builder => builder
            .FromGet("/proxy/files/{id}")
            .ToBackend("GET", "https://backend.test/files/{id}")
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/proxy/files/42", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task ModifyResponseHeaders_RemovesInternalHeader_BeforeBodyIsWritten()
    {
        // Regression: ModifyResponseHeaders was called *after* headers were already
        // copied to context.Response.Headers and operated on the inbound HttpClient
        // headers rather than the outgoing ones, so it was a no-op. The fix invokes
        // the hook before the copy step.
        using var bff = await CreateBffAsync<HeaderScrubbingTransformer>(builder => builder
            .FromGet("/proxy/files/{id}")
            .ToBackend("GET", "https://backend.test/files/{id}")
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/proxy/files/42", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.False(
            response.Headers.Contains("X-Internal-Debug"),
            "ModifyResponseHeaders should be able to scrub backend headers from the client response");
    }

    private static Task<IHost> CreateBffAsync(
        Action<RawForwardEndpointBuilder<DefaultRawForwardTransformer>> configure)
        => CreateBffInternalAsync<DefaultRawForwardTransformer>(configure);

    private static Task<IHost> CreateBffAsync<TTransformer>(
        Action<RawForwardEndpointBuilder<TTransformer>> configure)
        where TTransformer : class, IRawTransformer
        => CreateBffInternalAsync(configure);

    private static async Task<IHost> CreateBffInternalAsync<TTransformer>(
        Action<RawForwardEndpointBuilder<TTransformer>> configure)
        where TTransformer : class, IRawTransformer
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<IBackendCaller, FakeRawBackendCaller>();
                    services.AddSingleton(Options.Create(new PortaCoreOptions
                    {
                        RequireAuthorizationByDefault = false,
                    }));
                    services.AddScoped<TTransformer>();
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        var builder = endpoints.MapRawForward<TTransformer>();
                        configure(builder);
                        builder.Build();
                    });
                });
            });

        var host = await hostBuilder.StartAsync();
        return host;
    }

    /// <summary>
    /// Custom backend caller that returns a real HttpResponseMessage with sensitive
    /// response headers, so we can exercise the response-side filter end-to-end.
    /// </summary>
    private sealed class FakeRawBackendCaller : IBackendCaller
    {
        public Task<RawBackendResult> CallRawAsync(BackendRequest request, CancellationToken cancellationToken)
            => Task.FromResult(BuildResult());

        public Task<RawBackendResult> CallRawAsync(BackendRequest request, Stream requestBody, string contentType, CancellationToken cancellationToken)
            => Task.FromResult(BuildResult());

        private static RawBackendResult BuildResult()
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true}", Encoding.UTF8, "application/json"),
            };
            // Sensitive response headers a malicious or chatty backend might send.
            response.Headers.TryAddWithoutValidation("Set-Cookie", "evil=1; Path=/");
            response.Headers.TryAddWithoutValidation("Strict-Transport-Security", "max-age=0");
            response.Headers.TryAddWithoutValidation("Content-Security-Policy", "default-src *");
            response.Headers.TryAddWithoutValidation("Server", "leaky-backend/9.9");
            response.Headers.TryAddWithoutValidation("X-Powered-By", "Express");
            response.Headers.TryAddWithoutValidation("X-Internal-Debug", "leak-me");
            return RawBackendResult.Success(response);
        }

        // Unused for raw-forward tests, but the interface requires implementations.
        public Task<BackendResult<TResponse>> CallAsync<TResponse>(BackendRequest request, CancellationToken cancellationToken)
            => throw new NotImplementedException();
        public Task<BackendResult<TResponse>> CallAsync<TRequest, TResponse>(BackendRequest request, TRequest body, CancellationToken cancellationToken)
            => throw new NotImplementedException();
        public Task<BackendResult> CallAsync(BackendRequest request, CancellationToken cancellationToken)
            => throw new NotImplementedException();
        public Task<BackendResult> CallAsync<TRequest>(BackendRequest request, TRequest body, CancellationToken cancellationToken)
            => throw new NotImplementedException();
        public Task<BackendObjectResult> CallAsync(BackendRequest request, Type responseType, CancellationToken cancellationToken)
            => throw new NotImplementedException();
        public Task<BackendObjectResult> CallWithBodyAsync(BackendRequest request, object body, Type responseType, CancellationToken cancellationToken)
            => throw new NotImplementedException();
        public Task<GraphQLResult<TResponse>> CallGraphQLAsync<TResponse>(BackendRequest request, string query, object? variables, string dataPath, string? operationName = null, CancellationToken cancellationToken = default)
            => throw new NotImplementedException();
    }

    /// <summary>
    /// Transformer that scrubs an internal debug header. Used to verify that the
    /// ModifyResponseHeaders hook is actually wired up to the outgoing response.
    /// </summary>
    public sealed class HeaderScrubbingTransformer : RawForwardTransformer
    {
        protected override void ModifyResponseHeaders(HttpResponseHeaders headers, TransformerContext context)
        {
            headers.Remove("X-Internal-Debug");
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
