using System.Net;
using System.Net.Http.Headers;
using System.Text;

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
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Regression tests for finding #6: a URL rewrite performed in
/// <see cref="RawForwardTransformer.ModifyRequest"/> used to be discarded - the backend was always
/// called with the originally interpolated URL despite the hook being documented to allow modifying
/// the URL. These tests assert the rewrite is honoured, that route interpolation still works when no
/// rewrite happens, and that a rewrite cannot smuggle sensitive client headers (or the user's OAuth
/// token) to a host the operator never allow-listed for them.
/// </summary>
[Collection(PortaActivitySourceCollection.Name)]
public sealed class RawForwardUrlMutationTests
{
    [Fact]
    public async Task ModifyRequest_RewritesRequestUri_BackendCalledWithRewrittenUrl()
    {
        var caller = new CapturingRawBackendCaller();
        using var bff = await CreateBffAsync<UrlRewritingTransformer>(caller, builder => builder
            .FromGet("/proxy/files/{id}")
            .ToBackend("GET", "https://original.test/files/{id}")
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/proxy/files/42", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal("https://rewritten.test/redirected/42", caller.LastRequest!.Url);
    }

    [Fact]
    public async Task NoRewrite_BackendCalledWithInterpolatedUrl()
    {
        // Control: without a rewrite, route interpolation and the original URL must still flow through.
        var caller = new CapturingRawBackendCaller();
        using var bff = await CreateBffAsync<DefaultRawForwardTransformer>(caller, builder => builder
            .FromGet("/proxy/files/{id}")
            .ToBackend("GET", "https://original.test/files/{id}")
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/proxy/files/42", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal("https://original.test/files/42", caller.LastRequest!.Url);
    }

    [Fact]
    public async Task RewriteToDifferentHost_StripsSensitiveClientHeaderScopedToOriginalHost()
    {
        // Authorization is allow-listed for the ORIGINAL host only. A rewrite to a different host
        // must not carry that client header to the new (un-allow-listed) destination.
        var caller = new CapturingRawBackendCaller();
        using var bff = await CreateBffAsync<UrlRewritingTransformer>(caller, builder => builder
            .FromGet("/proxy/files/{id}")
            .ToBackend("GET", "https://original.test/files/{id}")
            .AllowForwardingHeaders(["Authorization"], ["original.test"])
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Get, "/proxy/files/42");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer client-token");
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal("https://rewritten.test/redirected/42", caller.LastRequest!.Url);
        Assert.DoesNotContain(
            caller.LastRequest.Headers ?? new Dictionary<string, string>(),
            h => string.Equals(h.Key, "Authorization", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RewriteToDifferentHost_PreservesNonSensitiveClientHeader()
    {
        // The re-scope must only strip sensitive headers that are no longer allowed for the final
        // host; ordinary client headers must continue to flow after a rewrite.
        var caller = new CapturingRawBackendCaller();
        using var bff = await CreateBffAsync<UrlRewritingTransformer>(caller, builder => builder
            .FromGet("/proxy/files/{id}")
            .ToBackend("GET", "https://original.test/files/{id}")
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Get, "/proxy/files/42");
        request.Headers.TryAddWithoutValidation("X-Trace-Id", "abc-123");
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Contains(
            caller.LastRequest!.Headers ?? new Dictionary<string, string>(),
            h => string.Equals(h.Key, "X-Trace-Id", StringComparison.OrdinalIgnoreCase) && h.Value == "abc-123");
    }

    [Fact]
    public async Task RewrittenUrl_ToUntrustedHost_WithUserTokenPolicy_IsRejectedBeforeForwarding()
    {
        // The defense-in-depth gate that closes the SSRF / token-leak vector lives in BackendCaller and
        // is keyed off BackendRequest.Url - the same field the URL rewrite now populates. A user-identity
        // policy pointed at a host outside PortaCore:TrustedHosts must fail closed without ever sending.
        var handler = new RecordingHandler();
        var caller = CreateRealCaller(handler, trustedHosts: ["trusted.test"]);

        // Simulates what RawForwardEndpointBuilder hands to the caller after ModifyRequest rewrote the URL.
        var rewritten = new BackendRequest
        {
            Method = "GET",
            Url = "https://untrusted.test/redirected/42",
            AccessToken = "user-token",
            BackendAuthPolicy = BackendAuthPolicies.BearerToken,
        };

        using var result = await caller.CallRawAsync(rewritten, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Null(handler.LastRequest); // never sent: token was not forwarded to the untrusted host
    }

    private static Task<IHost> CreateBffAsync<TTransformer>(
        IBackendCaller caller,
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
                    services.AddSingleton(caller);
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

        return hostBuilder.StartAsync();
    }

    private static BackendCaller CreateRealCaller(HttpMessageHandler handler, string[] trustedHosts)
    {
        // The trusted-host gate fires before backend-auth handler resolution, so the BearerToken
        // handler itself never needs to run for this test - registering None is enough.
        var registry = new BackendAuthHandlerRegistry();
        registry.Register(new NoneAuthHandler());

        var options = Options.Create(new PortaCoreOptions { TrustedHosts = [.. trustedHosts] });
        var validator = new TrustedHostValidator(options, NullLogger<TrustedHostValidator>.Instance);

        return new BackendCaller(
            new SingleHandlerHttpClientFactory(handler),
            registry,
            new ContentSerializer(),
            metrics: null,
            logger: NullLogger<BackendCaller>.Instance,
            coreOptions: options,
            trustedHostValidator: validator);
    }

    /// <summary>Rewrites the backend URL (and host) inside the documented ModifyRequest hook.</summary>
    private sealed class UrlRewritingTransformer : RawForwardTransformer
    {
        protected override void ModifyRequest(HttpRequestMessage request, TransformerContext context)
        {
            var id = context.RouteValues.TryGetValue("id", out var v) ? v?.ToString() : null;
            request.RequestUri = new Uri($"https://rewritten.test/redirected/{id}");
        }
    }

    /// <summary>Captures the <see cref="BackendRequest"/> the endpoint hands to the caller.</summary>
    private sealed class CapturingRawBackendCaller : IBackendCaller
    {
        public BackendRequest? LastRequest { get; private set; }

        public Task<RawBackendResult> CallRawAsync(BackendRequest request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(BuildResult());
        }

        public Task<RawBackendResult> CallRawAsync(BackendRequest request, Stream requestBody, string contentType, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(BuildResult());
        }

        private static RawBackendResult BuildResult()
            => RawBackendResult.Success(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true}", Encoding.UTF8, "application/json"),
            });

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

    /// <summary>Records the outbound request; if it is ever invoked the trusted-host gate failed to block.</summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class SingleHandlerHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
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
