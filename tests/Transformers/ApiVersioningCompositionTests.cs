using Asp.Versioning;
using Asp.Versioning.Builder;

using b17s.Porta.Tests.Fixtures;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Guards the two API-versioning patterns documented in docs/advanced.md against regression.
///
/// Both have bitten us before in docs-only form: the version examples are not exercised by the
/// rest of the suite, so a routing-semantics change would silently break the doc without any
/// test failing. These run the documented snippets end-to-end.
/// </summary>
public sealed class ApiVersioningCompositionTests
{
    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = "";
    }

    // ---- Option A: lightweight versioning with .When() ----
    //
    // A guarded endpoint (v2) plus an UNGUARDED fallback (v1) on the same route is the documented
    // shape: the guard wins when its predicate is true, the unguarded endpoint catches everything
    // else. WhenPredicateMatcherPolicy resolves the same-route tie so this does NOT throw
    // AmbiguousMatchException.

    [Theory]
    [InlineData("2", "v2")]   // X-Api-Version: 2 -> v2 guard true, v2 wins over the fallback
    [InlineData(null, "v1")]  // no header        -> v2 guard false, unguarded fallback serves it
    [InlineData("9", "v1")]   // unknown version  -> v2 guard false, fallback serves it
    public async Task When_GuardedPlusUnguardedFallback_SelectsExactlyOne(string? versionHeader, string expected)
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://v2.internal/products", new EchoResponse { Echoed = "v2" })
            .SetupResponse("https://v1.internal/products", new EchoResponse { Echoed = "v1" });

        using var bff = await CreateBffAsync(
            backend,
            configureServices: services =>
                services.AddSingleton<MatcherPolicy, WhenPredicateMatcherPolicy>(),
            configureEndpoints: app =>
            {
                // v2: opt in via header
                app.MapPassThrough<EchoResponse>()
                    .FromGet("/api/products")
                    .When(ctx => ctx.Request.Headers["X-Api-Version"] == "2")
                    .ToBackend("GET", "https://v2.internal/products")
                    .AllowAnonymous()
                    .Build();

                // v1: unguarded fallback on the same route
                app.MapPassThrough<EchoResponse>()
                    .FromGet("/api/products")
                    .ToBackend("GET", "https://v1.internal/products")
                    .AllowAnonymous()
                    .Build();
            });

        var client = bff.GetTestServer().CreateClient();
        if (versionHeader is not null)
        {
            client.DefaultRequestHeaders.Add("X-Api-Version", versionHeader);
        }

        var response = await client.GetAsync("/api/products", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains($"\"{expected}\"", body);
    }

    // Two guarded endpoints on the same route whose predicates are BOTH true is a genuine conflict
    // the policy must not paper over — it should still surface as an ambiguous match.
    [Fact]
    public async Task When_TwoOverlappingGuardsBothTrue_StillAmbiguous()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://a.internal/x", new EchoResponse { Echoed = "a" })
            .SetupResponse("https://b.internal/x", new EchoResponse { Echoed = "b" });

        using var bff = await CreateBffAsync(
            backend,
            configureServices: services =>
                services.AddSingleton<MatcherPolicy, WhenPredicateMatcherPolicy>(),
            configureEndpoints: app =>
            {
                app.MapPassThrough<EchoResponse>()
                    .FromGet("/api/x").When(_ => true)
                    .ToBackend("GET", "https://a.internal/x").AllowAnonymous().Build();
                app.MapPassThrough<EchoResponse>()
                    .FromGet("/api/x").When(_ => true)
                    .ToBackend("GET", "https://b.internal/x").AllowAnonymous().Build();
            });

        // AmbiguousMatchException is internal in ASP.NET Core, so assert on the type name.
        var ex = await Assert.ThrowsAnyAsync<Exception>(
            () => bff.GetTestServer().CreateClient().GetAsync("/api/x", TestContext.Current.CancellationToken));
        Assert.Equal("AmbiguousMatchException", ex.GetType().Name);
    }

    // ---- Option B: Asp.Versioning v10 with the NewVersionedApi group idiom ----
    //
    // Porta builders host on any IEndpointRouteBuilder, so a versioned RouteGroupBuilder
    // from NewVersionedApi(...).MapGroup(...).HasApiVersion(...) is a valid host. This proves
    // the .NET 10 idiom documented in Option B actually routes through Porta endpoints.

    [Theory]
    [InlineData("/api/v1/products", "v1")]
    [InlineData("/api/v2/products", "v2")]
    public async Task NewVersionedApi_GroupHostsPortaEndpoint(string path, string expected)
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://v1.internal/products", new EchoResponse { Echoed = "v1" })
            .SetupResponse("https://v2.internal/products", new EchoResponse { Echoed = "v2" });

        using var bff = await CreateBffAsync(
            backend,
            configureServices: services => services.AddApiVersioning(options =>
            {
                options.ApiVersionReader = new UrlSegmentApiVersionReader();
            }),
            configureEndpoints: app =>
            {
                var catalog = app.NewVersionedApi("Catalog");

                var v1 = catalog.MapGroup("/api/v{version:apiVersion}").HasApiVersion(1.0);
                v1.MapPassThrough<EchoResponse>()
                    .FromGet("/products")
                    .ToBackend("GET", "https://v1.internal/products")
                    .AllowAnonymous()
                    .Build();

                var v2 = catalog.MapGroup("/api/v{version:apiVersion}").HasApiVersion(2.0);
                v2.MapPassThrough<EchoResponse>()
                    .FromGet("/products")
                    .ToBackend("GET", "https://v2.internal/products")
                    .AllowAnonymous()
                    .Build();
            });

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync(path, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains($"\"{expected}\"", body);
    }

    // Verifies the deprecation snippet: HasDeprecatedApiVersion on a versioned group plus
    // ReportApiVersions = true advertises the sunset info via response headers.
    [Fact]
    public async Task DeprecatedVersion_ReportsSunsetHeaders()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://v1.internal/products", new EchoResponse { Echoed = "v1" });

        using var bff = await CreateBffAsync(
            backend,
            configureServices: services => services.AddApiVersioning(options =>
            {
                options.ReportApiVersions = true;
                options.ApiVersionReader = new UrlSegmentApiVersionReader();
            }),
            configureEndpoints: app =>
            {
                var catalog = app.NewVersionedApi("Catalog");
                var v1 = catalog.MapGroup("/api/v{version:apiVersion}").HasDeprecatedApiVersion(1.0);
                v1.MapPassThrough<EchoResponse>()
                    .FromGet("/products")
                    .ToBackend("GET", "https://v1.internal/products")
                    .AllowAnonymous()
                    .Build();
            });

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/api/v1/products", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.True(response.Headers.Contains("api-deprecated-versions"));
    }

    private static async Task<IHost> CreateBffAsync(
        MockBackendCaller backend,
        Action<IServiceCollection> configureServices,
        Action<IEndpointRouteBuilder> configureEndpoints)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization();
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<IBackendCaller>(backend);
                    services.AddTransient(typeof(BackendForwardingTransformer<>));
                    configureServices(services);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthorization();
                    app.UseEndpoints(configureEndpoints);
                });
            });
        return await hostBuilder.StartAsync();
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
