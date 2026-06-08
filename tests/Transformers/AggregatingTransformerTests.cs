using b17s.Porta.Tests.Fixtures;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Tests for <see cref="AggregatingTransformer{TResponse}"/> and the supporting
/// <see cref="AggregatorBuilder"/>, <see cref="AggregatorResults"/>, and
/// <see cref="BackendCallOutcome"/> types.
/// </summary>
public sealed class AggregatingTransformerTests
{
    // -----------------------------
    // End-to-end transformer execution
    // -----------------------------

    [Fact]
    public async Task TransformAsync_AllBackendsSucceed_AllResultsAvailableInMapResults()
    {
        // Happy path: two parallel backends, both return data, MapResults composes them.
        var backend = new MockBackendCaller()
            .SetupResponse("http://user-service/users", new UserInfo { Id = "u1", Name = "ada" })
            .SetupResponse("http://product-service/products", new ProductInfo { Sku = "p9", Title = "thing" });

        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/users", null),
            ("ProductInfo", "GET", "http://product-service/products", null));

        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new TwoBackendAggregator();
        var enriched = await sut.TransformAsync(context);

        Assert.Equal("ada", enriched.UserName);
        Assert.Equal("thing", enriched.ProductTitle);
        Assert.True(enriched.IsFullyEnriched);
    }

    [Fact]
    public async Task TransformAsync_OneBackendThrows_OthersStillComplete_OutcomeFlagsTheThrow()
    {
        // Partial-failure goal: if one backend throws, the aggregator must still
        // surface the survivors' results - AND distinguish "threw" from "returned null"
        // so MapResults can render a degraded response intentionally.
        var backend = new MockBackendCaller()
            .SetupResponse("http://product-service/products", new ProductInfo { Sku = "p9", Title = "still here" })
            .SetDefaultHandler(req =>
            {
                if (req.Url.Contains("user-service", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("user backend exploded");
                return null;
            });

        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/users", null),
            ("ProductInfo", "GET", "http://product-service/products", null));

        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new OutcomeReportingAggregator();
        var report = await sut.TransformAsync(context);

        Assert.Equal(BackendCallOutcome.Threw, report.UserOutcome);
        Assert.Equal(BackendCallOutcome.Success, report.ProductOutcome);
        Assert.Equal("still here", report.ProductTitle);
        Assert.Null(report.UserName);
    }

    [Fact]
    public async Task TransformAsync_BackendCallFails_OutcomeIsFailed_NotReturnedNullOrThrew()
    {
        // A completed-but-unsuccessful BackendResult (HTTP 4xx/5xx) lands on Failed -
        // distinct from both ReturnedNull ("service answered, but has no data") and Threw
        // ("the call itself crashed"). MapResults can therefore degrade differently on
        // "service errored" vs "service has no data", even though both read null via Get<T>.
        var backend = new MockBackendCaller()
            .SetupFailure<UserInfo>("http://user-service/users", 404, "missing")
            .SetupFailure<ProductInfo>("http://product-service/products", 500, "down");

        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/users", null),
            ("ProductInfo", "GET", "http://product-service/products", null));

        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new OutcomeReportingAggregator();
        var report = await sut.TransformAsync(context);

        Assert.Equal(BackendCallOutcome.Failed, report.UserOutcome);
        Assert.Equal(BackendCallOutcome.Failed, report.ProductOutcome);
        Assert.True(report.UserFailed);
        Assert.False(report.UserThrew);
        Assert.NotEqual(BackendCallOutcome.ReturnedNull, report.UserOutcome);
        Assert.NotEqual(BackendCallOutcome.Threw, report.UserOutcome);
    }

    [Fact]
    public async Task TransformAsync_BackendReturnsSuccessfulNullPayload_OutcomeIsReturnedNull_NotFailed()
    {
        // HTTP 200 with an empty body: the call succeeded but produced no value. That is
        // ReturnedNull ("service has no data for this user"), which MapResults can now treat
        // differently from Failed ("service errored").
        var backend = new MockBackendCaller()
            .SetupResponse<UserInfo>("http://user-service/users", null!)
            .SetupResponse<ProductInfo>("http://product-service/products", null!);

        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/users", null),
            ("ProductInfo", "GET", "http://product-service/products", null));

        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new OutcomeReportingAggregator();
        var report = await sut.TransformAsync(context);

        Assert.Equal(BackendCallOutcome.ReturnedNull, report.UserOutcome);
        Assert.Equal(BackendCallOutcome.ReturnedNull, report.ProductOutcome);
        Assert.False(report.UserFailed);
    }

    [Fact]
    public async Task TransformAsync_WhenCancellationRequested_PropagatesInsteadOfMaskingAsThrew()
    {
        // A cancelled request (client disconnect or a global timeout) must abort the
        // transform. It must NOT be swallowed into Threw outcomes on every leg and a
        // 200 with null data. The OperationCanceledException is expected to propagate.
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var backend = new MockBackendCaller()
            .WithDelay(50)
            .SetupResponse("http://user-service/users", new UserInfo { Id = "u1" })
            .SetupResponse("http://product-service/products", new ProductInfo { Sku = "p1" });

        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/users", null),
            ("ProductInfo", "GET", "http://product-service/products", null));

        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: cts.Token);

        var sut = new OutcomeReportingAggregator();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sut.TransformAsync(context));
    }

    [Fact]
    public async Task TransformAsync_WithBodyFactory_SendsTheBodyToCallWithBodyAsync()
    {
        // Backends configured via .WithBody() must reach the CallWithBodyAsync path.
        var backend = new MockBackendCaller()
            .SetupResponse("http://user-service/users", new UserInfo { Id = "u1", Name = "ada" });

        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "POST", "http://user-service/users", null));

        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new BodyAggregator();
        await sut.TransformAsync(context);

        // The mock records the body that was sent.
        Assert.NotNull(backend.LastCall);
        var body = backend.LastCall!.GetBody<UserLookup>();
        Assert.NotNull(body);
        Assert.Equal("12345", body!.UserId);
    }

    [Fact]
    public async Task TransformAsync_WithRouteValuesFactory_InterpolatesBackendUrlFromFactoryValues()
    {
        // A backend configured via .WithRouteValues() must have the factory's values
        // interpolated into its URL template. Before the fix the factory was stored but
        // never read, so the call hit the un-interpolated template.
        var backend = new MockBackendCaller()
            .SetupResponse("http://user-service/users/u42", new UserInfo { Id = "u42", Name = "ada" });

        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/users/{userId}", null));

        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new RouteValuesAggregator();
        var result = await sut.TransformAsync(context);

        Assert.NotNull(backend.LastCall);
        Assert.Equal("http://user-service/users/u42", backend.LastCall!.Request.Url);
        Assert.Equal("ada", result.Name);
    }

    [Fact]
    public async Task TransformAsync_WithRouteValuesFactory_AmbientRouteValuesWinOnCollision()
    {
        // Merge semantics match MultiBackendCalls.CallNamedBackendAsync: on a key collision the
        // ambient route value wins; the factory only fills keys the request didn't provide. The
        // factory supplies userId="u42", but the ambient userId="ambient-wins" must be kept.
        var backend = new MockBackendCaller()
            .SetupResponse("http://user-service/users/ambient-wins", new UserInfo { Id = "ambient-wins" });

        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/users/{userId}", null));

        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            routeValues: new Dictionary<string, object?> { ["userId"] = "ambient-wins" },
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new RouteValuesAggregator();
        await sut.TransformAsync(context);

        Assert.NotNull(backend.LastCall);
        Assert.Equal("http://user-service/users/ambient-wins", backend.LastCall!.Request.Url);
    }

    [Fact]
    public async Task TransformAsync_BuilderCachedAcrossCalls_ConfigureRunsOnce()
    {
        // GetOrCreateBuilder caches the builder so Configure() doesn't re-run on
        // every request. If this regresses we'd re-allocate backend configs on
        // every transform - cheap but pointless.
        var backend = new MockBackendCaller()
            .SetupResponse("http://user-service/users", new UserInfo { Id = "u1", Name = "ada" });
        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/users", null));

        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new CountingAggregator();

        await sut.TransformAsync(context);
        await sut.TransformAsync(context);
        await sut.TransformAsync(context);

        Assert.Equal(1, sut.ConfigureCallCount);
    }

    // -----------------------------
    // AggregatorResults surface (legacy constructor + explicit-outcome constructor)
    // -----------------------------

    [Fact]
    public void AggregatorResults_LegacyConstructor_InfersOutcomesFromNullness()
    {
        // The single-arg constructor builds outcomes from the results dict so older
        // call sites still get Success/ReturnedNull, but never see Threw.
        var transformer = new AggregatorIntrospector();
        var results = transformer.BuildLegacyResults(new Dictionary<string, object?>
        {
            ["alpha"] = new UserInfo { Id = "a" },
            ["beta"] = null,
        });

        Assert.Equal(BackendCallOutcome.Success, results.GetOutcome("alpha"));
        Assert.Equal(BackendCallOutcome.ReturnedNull, results.GetOutcome("beta"));
        Assert.False(results.Threw("alpha"));
        Assert.False(results.Threw("beta"));
    }

    [Fact]
    public void AggregatorResults_Get_ReturnsTypedValueOrNullForFailures()
    {
        var transformer = new AggregatorIntrospector();
        var results = transformer.BuildLegacyResults(new Dictionary<string, object?>
        {
            ["user"] = new UserInfo { Id = "u1", Name = "ada" },
            ["product"] = null,
        });

        Assert.Equal("ada", results.Get<UserInfo>("user")!.Name);
        Assert.Null(results.Get<UserInfo>("product"));
        Assert.Null(results.Get<UserInfo>("missing"));
    }

    [Fact]
    public void AggregatorResults_Get_WrongTypeParameter_ThrowsInsteadOfReturningNull()
    {
        // A present, non-null value whose runtime type doesn't match T is a programmer
        // error - Get<T> disagreeing with the Backend<T> registration. Surfacing it stops
        // a type-parameter typo from masquerading as "the backend had no data".
        var transformer = new AggregatorIntrospector();
        var results = transformer.BuildLegacyResults(new Dictionary<string, object?>
        {
            ["user"] = new UserInfo { Id = "u1", Name = "ada" },
        });

        var ex = Assert.Throws<InvalidOperationException>(() => results.Get<ProductInfo>("user"));
        Assert.Contains("ProductInfo", ex.Message);
        Assert.Contains("UserInfo", ex.Message);
    }

    [Fact]
    public void AggregatorResults_GetOrDefault_FillsInWhenAbsent()
    {
        var transformer = new AggregatorIntrospector();
        var fallback = new UserInfo { Id = "fallback" };
        var results = transformer.BuildLegacyResults(new Dictionary<string, object?>
        {
            ["user"] = null,
        });

        Assert.Same(fallback, results.GetOrDefault("user", fallback));
        Assert.Same(fallback, results.GetOrDefault("missing", fallback));
    }

    [Fact]
    public void AggregatorResults_HasResult_TrueOnlyForNonNull()
    {
        var transformer = new AggregatorIntrospector();
        var results = transformer.BuildLegacyResults(new Dictionary<string, object?>
        {
            ["user"] = new UserInfo(),
            ["product"] = null,
        });

        Assert.True(results.HasResult("user"));
        Assert.False(results.HasResult("product"));
        Assert.False(results.HasResult("missing"));
    }

    [Fact]
    public void AggregatorResults_AllSucceeded_RequiresEveryNamedResult()
    {
        var transformer = new AggregatorIntrospector();
        var results = transformer.BuildLegacyResults(new Dictionary<string, object?>
        {
            ["a"] = new UserInfo(),
            ["b"] = new UserInfo(),
            ["c"] = null,
        });

        Assert.True(results.AllSucceeded("a", "b"));
        Assert.False(results.AllSucceeded("a", "b", "c"));
        Assert.False(results.AllSucceeded("missing"));
    }

    [Fact]
    public void AggregatorResults_SuccessCount_AndNames_ExposeBookkeeping()
    {
        var transformer = new AggregatorIntrospector();
        var results = transformer.BuildLegacyResults(new Dictionary<string, object?>
        {
            ["a"] = new UserInfo(),
            ["b"] = null,
            ["c"] = new UserInfo(),
        });

        Assert.Equal(2, results.SuccessCount);
        Assert.Equal(new[] { "a", "b", "c" }, results.Names.OrderBy(n => n));
    }

    [Fact]
    public void AggregatorResults_MissingNameGetOutcome_ReturnsReturnedNull()
    {
        // Defensive lookup: an unknown name shouldn't throw - it reads as
        // ReturnedNull so MapResults can treat it uniformly with backends that
        // produced no payload.
        var transformer = new AggregatorIntrospector();
        var results = transformer.BuildLegacyResults(new Dictionary<string, object?>());

        Assert.Equal(BackendCallOutcome.ReturnedNull, results.GetOutcome("missing"));
        Assert.False(results.Threw("missing"));
    }

    // -----------------------------
    // Test aggregators
    // -----------------------------

    private sealed class TwoBackendAggregator : AggregatingTransformer<EnrichedProfile>
    {
        protected override void Configure(AggregatorBuilder builder)
        {
            builder.Backend<UserInfo>("UserInfo");
            builder.Backend<ProductInfo>("ProductInfo");
        }

        protected override EnrichedProfile MapResults(AggregatorResults results, TransformerContext context)
        {
            var user = results.Get<UserInfo>("UserInfo");
            var product = results.Get<ProductInfo>("ProductInfo");
            return new EnrichedProfile
            {
                UserName = user?.Name,
                ProductTitle = product?.Title,
                IsFullyEnriched = user != null && product != null,
            };
        }
    }

    private sealed class OutcomeReportingAggregator : AggregatingTransformer<OutcomeReport>
    {
        protected override void Configure(AggregatorBuilder builder)
        {
            builder.Backend<UserInfo>("UserInfo");
            builder.Backend<ProductInfo>("ProductInfo");
        }

        protected override OutcomeReport MapResults(AggregatorResults results, TransformerContext context)
        {
            return new OutcomeReport
            {
                UserOutcome = results.GetOutcome("UserInfo"),
                ProductOutcome = results.GetOutcome("ProductInfo"),
                UserFailed = results.Failed("UserInfo"),
                UserThrew = results.Threw("UserInfo"),
                UserName = results.Get<UserInfo>("UserInfo")?.Name,
                ProductTitle = results.Get<ProductInfo>("ProductInfo")?.Title,
            };
        }
    }

    private sealed class BodyAggregator : AggregatingTransformer<UserInfo>
    {
        protected override void Configure(AggregatorBuilder builder)
        {
            builder.Backend<UserInfo>("UserInfo")
                .WithBody(ctx => new UserLookup { UserId = ctx.UserId! });
        }

        protected override UserInfo MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<UserInfo>("UserInfo") ?? new UserInfo();
    }

    private sealed class RouteValuesAggregator : AggregatingTransformer<UserInfo>
    {
        protected override void Configure(AggregatorBuilder builder)
        {
            builder.Backend<UserInfo>("UserInfo")
                .WithRouteValues(_ => new Dictionary<string, object?> { ["userId"] = "u42" });
        }

        protected override UserInfo MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<UserInfo>("UserInfo") ?? new UserInfo();
    }

    private sealed class CountingAggregator : AggregatingTransformer<UserInfo>
    {
        public int ConfigureCallCount { get; private set; }

        protected override void Configure(AggregatorBuilder builder)
        {
            ConfigureCallCount++;
            builder.Backend<UserInfo>("UserInfo");
        }

        protected override UserInfo MapResults(AggregatorResults results, TransformerContext context)
            => results.Get<UserInfo>("UserInfo") ?? new UserInfo();
    }

    /// <summary>
    /// Test helper that exposes the internal <see cref="AggregatorResults"/> legacy
    /// constructor - it's internal in production but reachable via reflection so we
    /// can exercise it directly rather than driving it through a full transform.
    /// </summary>
    private sealed class AggregatorIntrospector
    {
        public AggregatorResults BuildLegacyResults(IReadOnlyDictionary<string, object?> results)
        {
            var ctor = typeof(AggregatorResults).GetConstructor(
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
                binder: null,
                types: new[] { typeof(IReadOnlyDictionary<string, object?>) },
                modifiers: null);
            Assert.NotNull(ctor);
            return (AggregatorResults)ctor!.Invoke(new object[] { results });
        }
    }

    // -----------------------------
    // Payload types used by the test aggregators
    // -----------------------------

    private sealed class UserInfo
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
    }

    private sealed class ProductInfo
    {
        public string Sku { get; set; } = "";
        public string Title { get; set; } = "";
    }

    private sealed class UserLookup
    {
        public string UserId { get; set; } = "";
    }

    private sealed class EnrichedProfile
    {
        public string? UserName { get; set; }
        public string? ProductTitle { get; set; }
        public bool IsFullyEnriched { get; set; }
    }

    private sealed class OutcomeReport
    {
        public BackendCallOutcome UserOutcome { get; set; }
        public BackendCallOutcome ProductOutcome { get; set; }
        public bool UserFailed { get; set; }
        public bool UserThrew { get; set; }
        public string? UserName { get; set; }
        public string? ProductTitle { get; set; }
    }
}
