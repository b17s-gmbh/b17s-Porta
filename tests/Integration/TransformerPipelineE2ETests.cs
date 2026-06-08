using System.Net.Http.Json;
using System.Net.Mime;

using b17s.Porta.Configuration;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Integration;

/// <summary>
/// End-to-end coverage for the transformer pipeline driven over real HTTP via
/// <see cref="PortaTestHost"/> + <see cref="FakeBackend"/>. Each test asserts on
/// Porta's response AND on what the backend actually received — wiring bugs
/// that pass unit tests show up here.
/// </summary>
public sealed class TransformerPipelineE2ETests
{
    private const string BackendBase = "http://backend.test";

    [Fact]
    public async Task MapPassThrough_ForwardsQueryAndReturnsBackendJson()
    {
        // Locks in the zero-code path: the BFF must deserialize the backend's JSON,
        // re-serialize it to the caller, and pass the inbound query string through
        // verbatim. Both halves regress easily — the backend's payload could be
        // dropped silently, or the query string could be stripped when the URL is
        // rebuilt from route values.
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/products", async ctx =>
        {
            ctx.Response.ContentType = MediaTypeNames.Application.Json;
            await ctx.Response.WriteAsJsonAsync(new EchoResponse { Echoed = "p9" });
        });

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/products")
                .ToBackend("GET", $"{BackendBase}/products")
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var client = bff.CreateAuthenticatedClient();
        var response = await client.GetAsync("/api/products?category=fruit&sort=asc", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<EchoResponse>(TestContext.Current.CancellationToken);
        Assert.Equal("p9", body!.Echoed);

        var recorded = Assert.Single(backend.ReceivedRequests);
        Assert.Equal("GET", recorded.Method);
        Assert.Equal("/products", recorded.Path);
        // Pass-through must forward the inbound query string to the *backend*, the same way the
        // raw-forward path does (RouteUrlInterpolator.AppendQueryString). Assert on the backend's
        // recorded query string specifically — not the client's outbound URI — so a regression that
        // drops the query when rebuilding the backend URL from route values is actually caught.
        Assert.Equal("?category=fruit&sort=asc", recorded.QueryString);
    }

    [Fact]
    public async Task MapPassThrough_MergesInboundQuery_WithBackendTemplateQuery()
    {
        // Typed pass-through shares RouteUrlInterpolator.AppendQueryString with the raw-forward
        // path, so the merge-with-existing-query case must behave identically: the inbound query
        // merges with '&', never a second '?'.
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/products", async ctx =>
        {
            ctx.Response.ContentType = MediaTypeNames.Application.Json;
            await ctx.Response.WriteAsJsonAsync(new EchoResponse { Echoed = "p9" });
        });

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/products")
                .ToBackend("GET", $"{BackendBase}/products?tenant=acme")
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/api/products?category=fruit", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var recorded = Assert.Single(backend.ReceivedRequests);
        Assert.Equal("/products", recorded.Path);
        // Exactly one '?' separator, both params present, merged with '&'.
        Assert.Equal("?tenant=acme&category=fruit", recorded.QueryString);
    }

    [Fact]
    public async Task MapTransformer_TransformsBackendResponse()
    {
        // A custom transformer can reshape the backend payload before returning it.
        // Asserting on both the projected response shape AND the backend recording
        // ensures the transformer ran (not bypassed) and that the underlying call
        // actually happened.
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/raw", async ctx =>
        {
            ctx.Response.ContentType = MediaTypeNames.Application.Json;
            await ctx.Response.WriteAsJsonAsync(new BackendUser { Id = "u-7", FullName = "Ada Lovelace" });
        });

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .ConfigureServices(services => services.AddTransformer<UserShapingTransformer>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<UserShapingTransformer, UserView>()
                .FromGet("/api/user")
                .ToBackend("GET", $"{BackendBase}/raw")
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/api/user", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var view = await response.Content.ReadFromJsonAsync<UserView>(TestContext.Current.CancellationToken);
        Assert.Equal("u-7", view!.UserId);
        Assert.Equal("ADA LOVELACE", view.DisplayName);
        Assert.Single(backend.ReceivedRequests);
    }

    [Fact]
    public async Task AggregatingTransformer_CombinesTwoBackends_ConcurrentCalls()
    {
        // Aggregator must fan out to both backends and merge results. Both backends
        // are required — if one is skipped the merged response would have a null
        // field, which the assertion catches.
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/userinfo", async ctx =>
        {
            await ctx.Response.WriteAsJsonAsync(new BackendUser { Id = "u-1", FullName = "Ada" });
        });
        backend.MapGet("/productinfo", async ctx =>
        {
            await ctx.Response.WriteAsJsonAsync(new BackendProduct { Sku = "p9", Title = "Difference Engine" });
        });

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .ConfigureServices(services => services.AddTransformer<TwoBackendAggregator>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<TwoBackendAggregator, EnrichedProfile>()
                .FromGet("/api/profile")
                .ToBackends(
                    NamedBackendEndpoint.FromTuple("UserInfo", "GET", $"{BackendBase}/userinfo"),
                    NamedBackendEndpoint.FromTuple("ProductInfo", "GET", $"{BackendBase}/productinfo"))
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/api/profile", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var enriched = await response.Content.ReadFromJsonAsync<EnrichedProfile>(TestContext.Current.CancellationToken);
        Assert.Equal("Ada", enriched!.UserName);
        Assert.Equal("Difference Engine", enriched.ProductTitle);

        Assert.Equal(2, backend.ReceivedRequests.Count);
        Assert.Contains(backend.ReceivedRequests, r => r.Path == "/userinfo");
        Assert.Contains(backend.ReceivedRequests, r => r.Path == "/productinfo");
    }

    [Fact]
    public async Task RawForward_StreamsBinaryResponse_WithHeadersFiltered()
    {
        // Raw forward must stream a binary body byte-for-byte and apply the response
        // header allow-list (Set-Cookie stripped, X-Custom passes through). The
        // RawForwardHeaderFilter unit tests cover the rules; this test verifies the
        // actual TestServer path applies them.
        var payload = Enumerable.Range(0, 1024).Select(i => (byte)(i % 256)).ToArray();

        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/blob", async ctx =>
        {
            ctx.Response.Headers["Set-Cookie"] = "evil=1; Path=/";
            ctx.Response.Headers["X-Custom-Trace"] = "abc-123";
            ctx.Response.Headers["Server"] = "secret-server";
            ctx.Response.ContentType = "application/octet-stream";
            await ctx.Response.Body.WriteAsync(payload);
        });

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .ConfigureServices(services => services.AddRawForwardTransformer<DefaultRawForwardTransformer>())
            .MapEndpoints(endpoints => endpoints
                .MapRawForward()
                .FromGet("/files/blob")
                .ToBackend("GET", $"{BackendBase}/blob")
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/files/blob", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken);
        Assert.Equal(payload, bytes);

        // Allow-listed by default: custom non-sensitive header survives.
        Assert.True(response.Headers.TryGetValues("X-Custom-Trace", out var custom));
        Assert.Equal("abc-123", custom!.Single());

        // Sensitive headers get stripped: a backend must not be able to plant cookies
        // on the BFF's domain, and Server is a fingerprinting leak.
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.False(response.Headers.Contains("Server"));
    }

    [Fact]
    public async Task RawForward_PostStreamsRequestBody()
    {
        // POST through raw-forward must stream the request body straight to the
        // backend without buffering. Send a non-trivial payload and assert the
        // backend received every byte intact.
        var sent = new byte[256 * 1024];
        new Random(17).NextBytes(sent);

        using var backend = new FakeBackend(BackendBase);
        backend.MapPost("/upload", ctx =>
        {
            ctx.Response.StatusCode = 201;
            return Task.CompletedTask;
        });

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .ConfigureServices(services => services.AddRawForwardTransformer<DefaultRawForwardTransformer>())
            .MapEndpoints(endpoints => endpoints
                .MapRawForward()
                .FromPost("/files")
                .ToBackend("POST", $"{BackendBase}/upload")
                .AllowAnonymous()
                .Build())
            .StartAsync();

        using var content = new ByteArrayContent(sent);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var response = await bff.CreateAuthenticatedClient()
            .PostAsync("/files", content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var recorded = Assert.Single(backend.ReceivedRequests);
        Assert.Equal("POST", recorded.Method);
        Assert.Equal(sent, recorded.BodyBytes);
    }

    [Fact]
    public async Task RawForward_MergesInboundQuery_WithBackendTemplateQuery()
    {
        // Spec §13 open item (b): the backend URL template may already carry a query string.
        // The inbound query must be merged with '&', not appended after a second '?', which
        // would produce a malformed URL ("...?tenant=acme?q=apple") and swallow the new params.
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/search", ctx => Task.CompletedTask);

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .ConfigureServices(services => services.AddRawForwardTransformer<DefaultRawForwardTransformer>())
            .MapEndpoints(endpoints => endpoints
                .MapRawForward()
                .FromGet("/api/search")
                .ToBackend("GET", $"{BackendBase}/search?tenant=acme")
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/api/search?q=apple", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.ReceivedRequests);
        Assert.Equal("/search", recorded.Path);
        // Exactly one '?' separator, both params present, merged with '&'.
        Assert.Equal("?tenant=acme&q=apple", recorded.QueryString);
    }

    [Fact]
    public async Task GraphQL_RestFacade_PostsQueryToBackend()
    {
        // A REST-facade transformer takes a GET, builds a GraphQL { query, variables }
        // envelope, posts to the backend, and extracts the dataPath. Verify both the
        // envelope shape (so the backend gets a real GraphQL request) and the
        // extracted data (so the dataPath actually projects).
        using var backend = new FakeBackend(BackendBase);
        backend.MapPost("/graphql", async ctx =>
        {
            ctx.Response.ContentType = MediaTypeNames.Application.Json;
            await ctx.Response.WriteAsync("""
                {
                    "data": {
                        "product": { "sku": "p9", "title": "Difference Engine" }
                    }
                }
                """);
        });

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .ConfigureServices(services => services.AddTransformer<ProductGraphQLTransformer>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<ProductGraphQLTransformer, BackendProduct>()
                .FromGet("/api/products/{sku}")
                .ToGraphQL($"{BackendBase}/graphql")
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/api/products/p9", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var product = await response.Content.ReadFromJsonAsync<BackendProduct>(TestContext.Current.CancellationToken);
        Assert.Equal("p9", product!.Sku);
        Assert.Equal("Difference Engine", product.Title);

        var recorded = Assert.Single(backend.ReceivedRequests);
        Assert.Equal("POST", recorded.Method);
        Assert.Equal("/graphql", recorded.Path);
        Assert.Contains("\"query\":", recorded.Body);
        Assert.Contains("\"variables\":", recorded.Body);
        Assert.Contains("\"sku\":\"p9\"", recorded.Body);
    }

    [Fact]
    public async Task BackendReturns500_PropagatesAsConfiguredError()
    {
        // The configured IBackendErrorMapper runs on the actual HTTP path, not just
        // unit-mock paths. Register a custom mapper that maps 500 -> 503; if the
        // mapper is bypassed we'd see 500 reach the caller instead.
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/broken", ctx =>
        {
            ctx.Response.StatusCode = 500;
            return ctx.Response.WriteAsync("backend exploded");
        });

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .ConfigureServices(services =>
            {
                // Replace the default 401/403 -> 502 mapper with one that re-maps
                // 5xx as well. The default would leave 500 alone, so a passing test
                // only proves the framework reaches the mapper.
                services.AddSingleton<IBackendErrorMapper, ServerErrorRemappingMapper>();
            })
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/broken")
                .ToBackend("GET", $"{BackendBase}/broken")
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/api/broken", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task BackendTimeout_ReturnsGatewayTimeout()
    {
        // BackendRequest.Timeout must fire on the real HTTP path. The backend
        // handler waits past the timeout; the BackendCaller catch block converts the
        // TaskCanceledException(TimeoutException) into a 504 mapping. The mock
        // version of this test never exercises the actual HttpClient timer.
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/slow", async ctx =>
        {
            // Let the cancellation propagate so HttpClient surfaces a
            // TaskCanceledException with TimeoutException inner — that's the
            // shape BackendCaller maps to 504.
            await Task.Delay(TimeSpan.FromSeconds(10), ctx.RequestAborted);
        });

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/slow")
                .ToBackend("GET", $"{BackendBase}/slow")
                .WithTimeout(TimeSpan.FromMilliseconds(200))
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/api/slow", TestContext.Current.CancellationToken);

        // BackendCaller maps a timeout to 504 via SendResult.Timeout, which
        // BackendForwardingTransformer surfaces as the response status.
        Assert.Equal(HttpStatusCode.GatewayTimeout, response.StatusCode);
    }

    [Fact]
    public async Task RouteParameterInterpolation_InjectsIntoBackendUrl()
    {
        // /users/{id} -> backend /users/42 with real ASP.NET route binding. Tests the
        // RouteUrlInterpolator on the live request path.
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/users/{id}", async ctx =>
        {
            var id = ctx.Request.RouteValues["id"]?.ToString();
            await ctx.Response.WriteAsJsonAsync(new BackendUser { Id = id ?? "?", FullName = "stub" });
        });

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<BackendUser>()
                .FromGet("/api/users/{id}")
                .ToBackend("GET", $"{BackendBase}/users/{{id}}")
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/api/users/42", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var user = await response.Content.ReadFromJsonAsync<BackendUser>(TestContext.Current.CancellationToken);
        Assert.Equal("42", user!.Id);

        var recorded = Assert.Single(backend.ReceivedRequests);
        Assert.Equal("/users/42", recorded.Path);
    }

    [Fact]
    public async Task TrustedHosts_RejectsUntrustedBackend_AtStartup()
    {
        // ToBackends(...) with .WithUserToken() against a host that isn't in
        // PortaCore:TrustedHosts must fail at startup, not at first request. The
        // failure is raised inside MapTransformer when the host bootstrap runs the
        // endpoint configuration delegate.
        var startTask = new PortaTestHost()
            .ConfigureCore(opts =>
            {
                opts.TrustedHosts = ["https://trusted.internal"];
                opts.RequireAuthorizationByDefault = false;
            })
            .WithAuthorization()
            .ConfigureServices(services => services.AddTransformer<TwoBackendAggregator>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<TwoBackendAggregator, EnrichedProfile>()
                .FromGet("/api/profile")
                .ToBackends(
                    ("UserInfo", "GET", $"{BackendBase}/userinfo").WithUserToken(),
                    NamedBackendEndpoint.FromTuple("ProductInfo", "GET", $"{BackendBase}/productinfo"))
                .RequireAuth()
                .Build())
            .StartAsync();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            using var host = await startTask;
        });
        Assert.Contains("not in the trusted hosts list", ex.Message);
    }

    [Fact]
    public async Task TrustedHosts_RejectsUntrustedBearerTokenBackend_AtStartup()
    {
        // C1 regression: a single-backend ToBackend(...) with the BearerToken policy forwards the
        // user's access token just like WithUserToken(), so it must clear PortaCore:TrustedHosts at
        // startup too. Before the fix only WithUserToken() was gated, letting a BearerToken backend
        // forward the token to an unvalidated host. No WithBackend() here, so the host never boots.
        var startTask = new PortaTestHost()
            .ConfigureCore(opts =>
            {
                opts.TrustedHosts = ["https://trusted.internal"];
                opts.RequireAuthorizationByDefault = false;
            })
            .WithAuthorization()
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<BackendUser>()
                .FromGet("/api/data")
                .ToBackend("GET", $"{BackendBase}/data")
                .WithBackendAuth(BackendAuthPolicies.BearerToken)
                .RequireAuth()
                .Build())
            .StartAsync();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            using var host = await startTask;
        });
        Assert.Contains("not in the trusted hosts list", ex.Message);
    }

    // -----------------------------
    // Supporting types
    // -----------------------------

    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = string.Empty;
    }

    public sealed class BackendUser
    {
        public string Id { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
    }

    public sealed class BackendProduct
    {
        public string Sku { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
    }

    public sealed class UserView
    {
        public string UserId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
    }

    public sealed class EnrichedProfile
    {
        public string? UserName { get; set; }
        public string? ProductTitle { get; set; }
    }

    /// <summary>
    /// Reshapes <see cref="BackendUser"/> into a <see cref="UserView"/> — covers
    /// the "transformer projects the backend payload" path. Calls the
    /// BackendCaller directly so the backend response type and the transformer's
    /// response type can differ.
    /// </summary>
    private sealed class UserShapingTransformer : ITransformer<UserView>
    {
        public async Task<UserView> TransformAsync(TransformerContext context)
        {
            var backendRequest = (BackendRequest)context.Properties["BackendRequest"];
            var result = await context.BackendCaller.CallAsync<BackendUser>(backendRequest, context.CancellationToken);
            var user = result.Value!;
            return new UserView
            {
                UserId = user.Id,
                DisplayName = user.FullName.ToUpperInvariant(),
            };
        }
    }

    private sealed class TwoBackendAggregator : AggregatingTransformer<EnrichedProfile>
    {
        protected override void Configure(AggregatorBuilder builder)
        {
            builder.Backend<BackendUser>("UserInfo");
            builder.Backend<BackendProduct>("ProductInfo");
        }

        protected override EnrichedProfile MapResults(AggregatorResults results, TransformerContext context)
        {
            var user = results.Get<BackendUser>("UserInfo");
            var product = results.Get<BackendProduct>("ProductInfo");
            return new EnrichedProfile
            {
                UserName = user?.FullName,
                ProductTitle = product?.Title,
            };
        }
    }

    /// <summary>
    /// REST→GraphQL adapter. Takes a route parameter, builds a GraphQL query +
    /// variables, posts it to the GraphQL endpoint, and extracts <c>data.product</c>.
    /// </summary>
    private sealed class ProductGraphQLTransformer : TransformerBase<BackendProduct>
    {
        private const string Query = "query GetProduct($sku: String!) { product(sku: $sku) { sku title } }";

        public override async Task<BackendProduct> TransformAsync(TransformerContext context)
        {
            InitializeLogger(context);
            var sku = GetRouteValue(context, "sku") ?? string.Empty;
            var backendRequest = (BackendRequest)context.Properties["BackendRequest"];

            var result = await context.BackendCaller.CallGraphQLAsync<BackendProduct>(
                backendRequest,
                Query,
                variables: new { sku },
                dataPath: "product",
                cancellationToken: context.CancellationToken);

            if (!result.IsSuccess)
            {
                context.HttpContext.Response.StatusCode = result.MappedStatusCode;
                await context.HttpContext.Response.WriteAsJsonAsync(
                    new { error = result.Error ?? "GraphQL failed" }, context.CancellationToken);
                return new BackendProduct();
            }
            return result.Data!;
        }
    }

    /// <summary>
    /// Custom error mapper used only by <see cref="BackendReturns500_PropagatesAsConfiguredError"/>:
    /// re-maps backend 5xx to 503 so the test can prove the mapper actually ran.
    /// </summary>
    private sealed class ServerErrorRemappingMapper : IBackendErrorMapper
    {
        public (int StatusCode, string Message) MapError(int backendStatusCode, string? backendError, BackendRequest request)
            => backendStatusCode >= 500
                ? (503, "Service unavailable")
                : (backendStatusCode, backendError ?? "Backend request failed");
    }
}
