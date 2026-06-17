using System.Collections.Concurrent;
using System.Diagnostics;

using b17s.Porta.Telemetry;
using b17s.Porta.Tests.Fixtures;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Tests for per-leg backend caching in <see cref="AggregatingTransformer{TResponse}"/> via the
/// <c>WithCache(...)</c> builder method: the cache key, the fail-closed safety model, outcome
/// preservation (failures are never cached), and the cache-hit telemetry tag.
/// </summary>
[Collection(PortaActivitySourceCollection.Name)]
public sealed class AggregatingTransformerCachingTests
{
    private const string SharedUrl = "http://weather-service/weather";
    private const string SecureUrl = "http://entitlements-service/entitlements";

    // -----------------------------
    // Cache key (BackendCacheKey.Build)
    // -----------------------------

    [Fact]
    public void CacheKey_SameInputs_ProducesSameKey()
    {
        var request = Get(SharedUrl);
        var ctx = NewContext();

        var a = BackendCacheKey.Build(SharedConfig(), request, body: null, ctx, "WeatherAggregator");
        var b = BackendCacheKey.Build(SharedConfig(), request, body: null, ctx, "WeatherAggregator");

        Assert.Equal(a, b);
        Assert.StartsWith("porta:agg:", a);
    }

    [Fact]
    public void CacheKey_DifferentResolvedUrl_ProducesDifferentKey()
    {
        var ctx = NewContext();

        var a = BackendCacheKey.Build(SharedConfig(), Get(SharedUrl + "/u1"), body: null, ctx, "WeatherAggregator");
        var b = BackendCacheKey.Build(SharedConfig(), Get(SharedUrl + "/u2"), body: null, ctx, "WeatherAggregator");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void CacheKey_DifferentBody_ProducesDifferentKey()
    {
        var ctx = NewContext();
        var config = SharedConfig();
        config.BodyFactory = _ => new { q = "x" };
        var request = Get(SharedUrl);

        var a = BackendCacheKey.Build(config, request, new { q = "x" }, ctx, "WeatherAggregator");
        var b = BackendCacheKey.Build(config, request, new { q = "y" }, ctx, "WeatherAggregator");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void CacheKey_DifferentTransformerName_IsolatesLegsOfTheSameName()
    {
        var request = Get(SharedUrl);
        var ctx = NewContext();

        var a = BackendCacheKey.Build(SharedConfig(), request, body: null, ctx, "AggregatorOne");
        var b = BackendCacheKey.Build(SharedConfig(), request, body: null, ctx, "AggregatorTwo");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void CacheKey_VaryByUser_PartitionsBySubject()
    {
        var request = Get(SecureUrl);
        var config = SharedConfig(varyByUser: true);

        var alice = BackendCacheKey.Build(config, request, null, ContextForUser("alice"), "WeatherAggregator");
        var bob = BackendCacheKey.Build(config, request, null, ContextForUser("bob"), "WeatherAggregator");

        Assert.NotEqual(alice, bob);
    }

    // -----------------------------
    // Cache hit / miss behaviour
    // -----------------------------

    [Fact]
    public async Task SharedLeg_SecondRequest_ServedFromCache_BackendCalledOnce()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse(SharedUrl, new Weather { City = "berlin", TempC = 21 });
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "GET", SharedUrl, BackendAuthPolicies.None));

        var first = await RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider);
        var second = await RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider);

        Assert.Equal("berlin", first.City);
        Assert.Equal("berlin", second.City);
        Assert.Single(backend.RecordedCalls); // second request hit the cache, not the backend
    }

    [Fact]
    public async Task SharedLeg_DifferentRouteValue_IsADifferentEntry_BackendCalledAgain()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller()
            .SetupResponse(SharedUrl + "/u1", new Weather { City = "berlin" })
            .SetupResponse(SharedUrl + "/u2", new Weather { City = "munich" });
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "GET", SharedUrl + "/{u}", BackendAuthPolicies.None));

        var r1 = await RunAsync<RouteWeatherAggregator, Weather>(
            namedBackends, backend, provider, routeValues: new() { ["u"] = "u1" });
        var r2 = await RunAsync<RouteWeatherAggregator, Weather>(
            namedBackends, backend, provider, routeValues: new() { ["u"] = "u2" });

        Assert.Equal("berlin", r1.City);
        Assert.Equal("munich", r2.City);
        Assert.Equal(2, backend.RecordedCalls.Count); // different resolved URLs -> distinct keys
    }

    [Fact]
    public async Task VaryByUser_DifferentUsers_DoNotShareAnEntry()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse(SecureUrl, new Weather { City = "x" });
        var namedBackends = TestFixtures.CreateNamedBackends(("Entitlements", "GET", SecureUrl, BackendAuthPolicies.BearerToken));

        await RunAsync<PerUserAggregator, Weather>(namedBackends, backend, provider, userId: "alice");
        await RunAsync<PerUserAggregator, Weather>(namedBackends, backend, provider, userId: "alice"); // cached for alice
        await RunAsync<PerUserAggregator, Weather>(namedBackends, backend, provider, userId: "bob");    // bob is a fresh entry

        Assert.Equal(2, backend.RecordedCalls.Count);
    }

    // -----------------------------
    // Safety model (fail-closed)
    // -----------------------------

    [Fact]
    public async Task UserVaryingLeg_CachedWithoutVaryByUser_Throws()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse(SecureUrl, new Weather());
        var namedBackends = TestFixtures.CreateNamedBackends(("Entitlements", "GET", SecureUrl, BackendAuthPolicies.BearerToken));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunAsync<UnsafeUserAggregator, Weather>(namedBackends, backend, provider));

        Assert.Contains("per-user key", ex.Message);
        Assert.Empty(backend.RecordedCalls); // failed closed before any backend call
    }

    [Fact]
    public async Task UserVaryingLeg_CachedWithVaryByButNotVaryByUser_StillThrows()
    {
        // A custom varyBy is an *extra* dimension Porta can't inspect, so it must NOT satisfy the
        // per-user requirement on an identity-forwarding leg: a varyBy that omits the subject would
        // re-open the cross-user leak. Only varyByUser counts.
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse(SecureUrl, new Weather());
        var namedBackends = TestFixtures.CreateNamedBackends(("Entitlements", "GET", SecureUrl, BackendAuthPolicies.BearerToken));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunAsync<VaryByOnlyUserAggregator, Weather>(namedBackends, backend, provider));

        Assert.Contains("per-user key", ex.Message);
        Assert.Empty(backend.RecordedCalls); // failed closed before any backend call
    }

    [Fact]
    public async Task VaryByUser_WithNullSubject_Throws()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse(SecureUrl, new Weather());
        var namedBackends = TestFixtures.CreateNamedBackends(("Entitlements", "GET", SecureUrl, BackendAuthPolicies.BearerToken));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunAsync<PerUserAggregator, Weather>(namedBackends, backend, provider, userId: null));

        Assert.Contains("no authenticated subject", ex.Message);
    }

    [Fact]
    public async Task SharedLeg_CachesWithoutVaryByUser_NoThrow()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse(SharedUrl, new Weather { City = "berlin" });
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "GET", SharedUrl, BackendAuthPolicies.None));

        var result = await RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider);

        Assert.Equal("berlin", result.City);
    }

    [Fact]
    public async Task NonGetLeg_CannotBeCached_Throws()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse(SharedUrl, new Weather());
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "POST", SharedUrl, BackendAuthPolicies.None));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider));

        Assert.Contains("GET and HEAD", ex.Message);
    }

    [Fact]
    public async Task HybridCacheNotRegistered_Throws_WithRemediation()
    {
        using var provider = new ServiceCollection().BuildServiceProvider(); // no AddHybridCache()
        var backend = new MockBackendCaller().SetupResponse(SharedUrl, new Weather());
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "GET", SharedUrl, BackendAuthPolicies.None));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider));

        Assert.Contains("AddHybridCache()", ex.Message);
    }

    // -----------------------------
    // Outcome preservation
    // -----------------------------

    [Fact]
    public async Task FailedResponse_IsNeverCached_BackendRetriedOnNextRequest()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupFailure<Weather>(SharedUrl, 500, "down");
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "GET", SharedUrl, BackendAuthPolicies.None));

        var first = await RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider);
        var second = await RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider);

        Assert.Null(first);  // unsuccessful -> no value mapped
        Assert.Null(second);
        Assert.Equal(2, backend.RecordedCalls.Count); // failure not cached: backend re-called
    }

    [Fact]
    public async Task ReturnedNullPayload_IsCached_BackendCalledOnce()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse<Weather>(SharedUrl, null!); // 200 with null payload
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "GET", SharedUrl, BackendAuthPolicies.None));

        await RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider);
        await RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider);

        Assert.Single(backend.RecordedCalls); // a null 200 is a valid, cacheable result
    }

    // -----------------------------
    // Telemetry
    // -----------------------------

    [Fact]
    public async Task CacheHitTag_FalseOnMiss_TrueOnHit()
    {
        var hits = new ConcurrentQueue<bool>();
        // Read the name first so the PortaActivitySource static constructor fully completes before the
        // listener is attached - otherwise ShouldListenTo re-enters the cctor while it is still running.
        var sourceName = PortaActivitySource.Source.Name;
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a =>
            {
                if (a.OperationName == PortaActivitySource.Activities.BackendCall
                    && (string?)a.GetTagItem("aggregator.transformer") == nameof(SharedWeatherAggregator)
                    && a.GetTagItem("cache.hit") is bool hit)
                {
                    hits.Enqueue(hit);
                }
            },
        };
        ActivitySource.AddActivityListener(listener);

        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse(SharedUrl, new Weather { City = "berlin" });
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "GET", SharedUrl, BackendAuthPolicies.None));

        await RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider, telemetryEnabled: true);
        await RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider, telemetryEnabled: true);

        Assert.Equal([false, true], hits);
    }

    // -----------------------------
    // Stampede protection
    // -----------------------------

    [Fact]
    public async Task Stampede_ConcurrentColdRequests_CollapseToASingleBackendCall()
    {
        using var provider = BuildCacheProvider();
        // A slow backend keeps the single cold factory in flight long enough that every concurrent
        // request arrives before it completes - so HybridCache's stampede protection must collapse
        // them onto that one invocation rather than letting each miss call the backend.
        var backend = new MockBackendCaller()
            .SetupResponse(SharedUrl, new Weather { City = "berlin" })
            .WithDelay(150);
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "GET", SharedUrl, BackendAuthPolicies.None));

        const int concurrentRequests = 20;
        var tasks = new Task<Weather>[concurrentRequests];
        for (var i = 0; i < concurrentRequests; i++)
        {
            tasks[i] = RunAsync<SharedWeatherAggregator, Weather>(namedBackends, backend, provider);
        }
        var results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.Equal("berlin", r.City));
        Assert.Single(backend.RecordedCalls); // N cold requests -> exactly one backend invocation
    }

    // -----------------------------
    // Tag-based invalidation
    // -----------------------------

    [Fact]
    public async Task Tagged_RemoveByTagAsync_EvictsEntry_BackendCalledAgain()
    {
        using var provider = BuildCacheProvider();
        var cache = provider.GetRequiredService<HybridCache>();
        var backend = new MockBackendCaller().SetupResponse(SharedUrl, new Weather { City = "berlin" });
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "GET", SharedUrl, BackendAuthPolicies.None));

        await RunAsync<TaggedWeatherAggregator, Weather>(namedBackends, backend, provider);
        await RunAsync<TaggedWeatherAggregator, Weather>(namedBackends, backend, provider);
        Assert.Single(backend.RecordedCalls); // second served from cache

        // Webhook-driven eviction: drop everything tagged "weather", then the next request is a miss.
        await cache.RemoveByTagAsync("weather", TestContext.Current.CancellationToken);

        await RunAsync<TaggedWeatherAggregator, Weather>(namedBackends, backend, provider);
        Assert.Equal(2, backend.RecordedCalls.Count); // entry evicted -> backend re-called
    }

    // -----------------------------
    // GraphQL backend caching (WithGraphQLCache, POST)
    // -----------------------------

    [Fact]
    public async Task GraphQLLeg_SecondRequest_ServedFromCache_BackendCalledOnce()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse(SharedUrl, new Weather { City = "berlin" });
        // GraphQL rides POST; WithGraphQLCache opts the POST leg into caching that WithCache would reject.
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "POST", SharedUrl, BackendAuthPolicies.None));

        var first = await RunAsync<GraphQLWeatherAggregator, Weather>(namedBackends, backend, provider);
        var second = await RunAsync<GraphQLWeatherAggregator, Weather>(namedBackends, backend, provider);

        Assert.Equal("berlin", first.City);
        Assert.Equal("berlin", second.City);
        Assert.Single(backend.RecordedCalls); // POST GraphQL query cached, keyed by the request body
    }

    [Fact]
    public async Task GraphQLLeg_UserVaryingWithoutVaryByUser_Throws()
    {
        using var provider = BuildCacheProvider();
        var backend = new MockBackendCaller().SetupResponse(SecureUrl, new Weather());
        var namedBackends = TestFixtures.CreateNamedBackends(("Weather", "POST", SecureUrl, BackendAuthPolicies.BearerToken));

        // The fail-closed per-user safety guard still applies to WithGraphQLCache.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            RunAsync<GraphQLUnsafeUserAggregator, Weather>(namedBackends, backend, provider));

        Assert.Contains("per-user key", ex.Message);
        Assert.Empty(backend.RecordedCalls);
    }

    // -----------------------------
    // Startup cross-check (boot-time validation in Build())
    // -----------------------------

    [Fact]
    public void Startup_UserVaryingLegCachedWithoutVaryByUser_ThrowsAtBuild()
    {
        // The same fail-closed guard that runs at request time now fails the boot, before any
        // request reaches the misconfigured leg.
        using var app = WebApplication.CreateBuilder().Build();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            app.MapTransformer<StartupUnsafeUserAggregator, Weather>()
                .FromGet("/dash")
                .ToBackends(NamedBackendEndpoint.FromTuple("Entitlements", "GET", SecureUrl, BackendAuthPolicies.BearerToken))
                .RequireAuth()
                .Build());

        Assert.Contains("per-user key", ex.Message);
    }

    [Fact]
    public void Startup_CacheableLegWithoutHybridCache_ThrowsAtBuild()
    {
        using var app = WebApplication.CreateBuilder().Build(); // no AddHybridCache()

        var ex = Assert.Throws<InvalidOperationException>(() =>
            app.MapTransformer<StartupSharedAggregator, Weather>()
                .FromGet("/dash")
                .ToBackends(NamedBackendEndpoint.FromTuple("Weather", "GET", SharedUrl, BackendAuthPolicies.None))
                .AllowAnonymous()
                .Build());

        Assert.Contains("AddHybridCache", ex.Message);
    }

    [Fact]
    public void Startup_WellConfiguredCacheableLeg_DoesNotThrowAtBuild()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddHybridCache();
        using var app = builder.Build();

        var thrown = Record.Exception(() =>
            app.MapTransformer<StartupSharedAggregator, Weather>()
                .FromGet("/dash")
                .ToBackends(NamedBackendEndpoint.FromTuple("Weather", "GET", SharedUrl, BackendAuthPolicies.None))
                .AllowAnonymous()
                .Build());

        Assert.Null(thrown);
    }

    // -----------------------------
    // Helpers
    // -----------------------------


    private static ServiceProvider BuildCacheProvider()
    {
        var services = new ServiceCollection();
        services.AddHybridCache();
        return services.BuildServiceProvider();
    }

    private static async Task<TResponse> RunAsync<TTransformer, TResponse>(
        NamedBackendEndpoints namedBackends,
        MockBackendCaller backend,
        IServiceProvider provider,
        string? userId = "12345",
        Dictionary<string, object?>? routeValues = null,
        bool telemetryEnabled = false)
        where TTransformer : AggregatingTransformer<TResponse>, new()
    {
        var http = TestFixtures.CreateHttpContext(serviceProvider: provider);
        var context = new TransformerContext
        {
            AuthContext = TestFixtures.CreateAuthContext(userId: userId),
            BackendCaller = backend,
            HttpContext = http,
            RouteValues = routeValues ?? [],
            QueryParameters = new Dictionary<string, StringValues>(),
            RequestHeaders = new Dictionary<string, StringValues>(),
            Properties = new Dictionary<string, object> { ["NamedBackends"] = namedBackends },
            Logger = NullLogger.Instance,
            TelemetryEnabled = telemetryEnabled,
            CancellationToken = TestContext.Current.CancellationToken,
        };

        return await new TTransformer().TransformAsync(context);
    }

    private static BackendRequest Get(string url) => new() { Method = "GET", Url = url };

    private static BackendCallConfig SharedConfig(bool varyByUser = false)
        => new("Weather", typeof(Weather))
        {
            // The Invoke delegate is unused by BackendCacheKey.Build, so a key-only test can omit it.
            Cache = new CacheSpec(TimeSpan.FromMinutes(5), varyByUser, VaryBy: null, Invoke: null!),
        };

    private static TransformerContext NewContext()
        => TestFixtures.CreateTransformerContext(cancellationToken: TestContext.Current.CancellationToken);

    private static TransformerContext ContextForUser(string userId)
        => TestFixtures.CreateTransformerContext(
            authContext: TestFixtures.CreateAuthContext(userId: userId),
            cancellationToken: TestContext.Current.CancellationToken);

    // -----------------------------
    // Test transformers + payloads
    // -----------------------------

    private sealed class SharedWeatherAggregator : AggregatingTransformer<Weather>
    {
        protected override void Configure(AggregatorBuilder builder)
            => builder.Backend<Weather>("Weather").WithCache(TimeSpan.FromMinutes(5));

        protected override Weather MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<Weather>("Weather")!;
    }

    private sealed class RouteWeatherAggregator : AggregatingTransformer<Weather>
    {
        protected override void Configure(AggregatorBuilder builder)
            => builder.Backend<Weather>("Weather").WithCache(TimeSpan.FromMinutes(5));

        protected override Weather MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<Weather>("Weather")!;
    }

    private sealed class PerUserAggregator : AggregatingTransformer<Weather>
    {
        protected override void Configure(AggregatorBuilder builder)
            => builder.Backend<Weather>("Entitlements").WithCache(TimeSpan.FromSeconds(30), varyByUser: true);

        protected override Weather MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<Weather>("Entitlements")!;
    }

    private sealed class UnsafeUserAggregator : AggregatingTransformer<Weather>
    {
        protected override void Configure(AggregatorBuilder builder)
            => builder.Backend<Weather>("Entitlements").WithCache(TimeSpan.FromSeconds(30)); // missing varyByUser

        protected override Weather MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<Weather>("Entitlements")!;
    }

    private sealed class VaryByOnlyUserAggregator : AggregatingTransformer<Weather>
    {
        protected override void Configure(AggregatorBuilder builder)
            // Identity-forwarding leg partitioned only by a custom (non-user) dimension - must still throw.
            => builder.Backend<Weather>("Entitlements")
                .WithCache(TimeSpan.FromSeconds(30), varyBy: _ => "tenant-1");

        protected override Weather MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<Weather>("Entitlements")!;
    }

    private sealed class TaggedWeatherAggregator : AggregatingTransformer<Weather>
    {
        protected override void Configure(AggregatorBuilder builder)
            => builder.Backend<Weather>("Weather").WithCache(TimeSpan.FromMinutes(5), tags: ["weather"]);

        protected override Weather MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<Weather>("Weather")!;
    }

    private sealed class GraphQLWeatherAggregator : AggregatingTransformer<Weather>
    {
        protected override void Configure(AggregatorBuilder builder)
            => builder.Backend<Weather>("Weather")
                .WithBody(_ => GraphQLExtensions.CreateRequest("query { weather { city } }"))
                .WithGraphQLCache(TimeSpan.FromMinutes(5));

        protected override Weather MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<Weather>("Weather")!;
    }

    private sealed class GraphQLUnsafeUserAggregator : AggregatingTransformer<Weather>
    {
        protected override void Configure(AggregatorBuilder builder)
            => builder.Backend<Weather>("Weather")
                .WithBody(_ => GraphQLExtensions.CreateRequest("query { me { id } }"))
                .WithGraphQLCache(TimeSpan.FromSeconds(30)); // user-varying leg, no varyByUser

        protected override Weather MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<Weather>("Weather")!;
    }

    // Startup-validation transformers are public so the boot-time cross-check can instantiate them
    // via ActivatorUtilities across the assembly boundary.
    public sealed class StartupSharedAggregator : AggregatingTransformer<Weather>
    {
        protected override void Configure(AggregatorBuilder builder)
            => builder.Backend<Weather>("Weather").WithCache(TimeSpan.FromMinutes(5));

        protected override Weather MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<Weather>("Weather")!;
    }

    public sealed class StartupUnsafeUserAggregator : AggregatingTransformer<Weather>
    {
        protected override void Configure(AggregatorBuilder builder)
            => builder.Backend<Weather>("Entitlements").WithCache(TimeSpan.FromSeconds(30)); // missing varyByUser

        protected override Weather MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<Weather>("Entitlements")!;
    }

    // Public so the public startup-validation aggregators can derive from AggregatingTransformer<Weather>
    // (and so it round-trips cleanly through the L2 serializer in the distributed-cache test).
    public sealed class Weather
    {
        public string City { get; set; } = "";
        public int TempC { get; set; }
    }
}
