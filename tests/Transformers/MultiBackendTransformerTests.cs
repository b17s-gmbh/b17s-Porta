using b17s.Porta.Tests.Fixtures;

using Microsoft.Extensions.Logging;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Direct unit tests for <see cref="MultiBackendTransformer{TResponse}"/> and
/// <see cref="MultiBackendTransformer{TRequest, TResponse}"/>. The aggregator base
/// covers the wiring on the success path indirectly; these tests target the protected
/// helpers head-on so the contract is locked even when a consumer derives from
/// MultiBackendTransformer directly instead of via AggregatingTransformer.
/// </summary>
public sealed class MultiBackendTransformerTests
{
    // -----------------------------
    // GetNamedBackends / CallNamedBackendAsync
    // -----------------------------

    [Fact]
    public async Task CallNamedBackendAsync_NoBody_DispatchesToParameterlessOverload()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://user-service/api/users", new UserInfo { Id = "u1", Name = "ada" });
        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/api/users", null));
        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new ExposedMultiBackend();
        var result = await sut.CallNamedBackendForTest<UserInfo>("UserInfo", context);

        Assert.True(result.IsSuccess);
        Assert.Equal("ada", result.Value!.Name);
        // Body must be null on this overload - exercised the no-body branch in CallNamedBackendAsync.
        Assert.Null(backend.LastCall!.Body);
    }

    [Fact]
    public async Task CallNamedBackendAsync_WithBody_DispatchesToBodyOverload()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://user-service/api/users", new UserInfo { Id = "u1", Name = "ada" });
        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "POST", "http://user-service/api/users", null));
        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new ExposedMultiBackend();
        var payload = new UserLookup { UserId = "12345" };
        var result = await sut.CallNamedBackendForTest<UserLookup, UserInfo>("UserInfo", payload, context);

        Assert.True(result.IsSuccess);
        // The non-null body must reach the CallAsync<TRequest, TResponse> overload.
        Assert.Same(payload, backend.LastCall!.GetBody<UserLookup>());
    }

    [Fact]
    public async Task CallNamedBackendAsync_MergesContextRouteValuesWithCallSiteOverrides()
    {
        // Route templates resolve from a merged dictionary: context.RouteValues + per-call extras.
        // Context wins on key collisions (the .Where filter in the source) - covers the conflict branch.
        var capturedUrls = new List<string>();
        var backend = new MockBackendCaller()
            .SetDefaultHandler(req =>
            {
                capturedUrls.Add(req.Url);
                return BackendResult<UserInfo>.Success(new UserInfo { Id = "u1" });
            });
        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/api/{tenant}/users/{id}", null));

        var contextRouteValues = new Dictionary<string, object?>
        {
            ["tenant"] = "acme",
            ["id"] = "from-context", // should win
        };
        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            routeValues: contextRouteValues,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new ExposedMultiBackend();
        var extras = new Dictionary<string, object?>
        {
            ["id"] = "from-extras",     // should be ignored - context already provides "id"
            ["extra"] = "ignored-key",  // unused by the URL template, harmless
        };

        await sut.CallNamedBackendForTest<UserInfo>("UserInfo", context, extras);

        // Context's "id" wins over the per-call value.
        Assert.Single(capturedUrls);
        Assert.Equal("http://user-service/api/acme/users/from-context", capturedUrls[0]);
    }

    [Fact]
    public async Task CallNamedBackendAsync_UsesCallSiteRouteValuesWhenContextLacksKey()
    {
        var capturedUrls = new List<string>();
        var backend = new MockBackendCaller()
            .SetDefaultHandler(req =>
            {
                capturedUrls.Add(req.Url);
                return BackendResult<UserInfo>.Success(new UserInfo { Id = "u1" });
            });
        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/api/{tenant}/users/{id}", null));

        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            routeValues: new Dictionary<string, object?> { ["tenant"] = "acme" },
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new ExposedMultiBackend();
        var extras = new Dictionary<string, object?> { ["id"] = "from-extras" };

        await sut.CallNamedBackendForTest<UserInfo>("UserInfo", context, extras);

        // Both keys must contribute: tenant from context, id from extras.
        Assert.Equal("http://user-service/api/acme/users/from-extras", capturedUrls[0]);
    }

    [Fact]
    public async Task GetNamedBackends_NoNamedBackendsConfigured_Throws()
    {
        // Failure-closed contract: forgetting to call ToBackends() must throw
        // a descriptive InvalidOperationException, not a NullReferenceException.
        var context = TestFixtures.CreateTransformerContext(
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new ExposedMultiBackend();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => sut.CallNamedBackendForTest<UserInfo>("UserInfo", context));

        Assert.Contains("ToBackends()", ex.Message);
    }

    // -----------------------------
    // CallBackendsInParallelAsync (strict, cancels siblings on first failure)
    // -----------------------------

    [Fact]
    public async Task CallBackendsInParallelAsync_AllSucceed_ReturnsResultsInOrder()
    {
        var context = TestFixtures.CreateTransformerContext(
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        var results = await sut.CallBackendsInParallelForTest<int>(
            new Func<CancellationToken, Task<int>>[]
            {
                async ct => { await Task.Yield(); return 1; },
                async ct => { await Task.Yield(); return 2; },
                async ct => { await Task.Yield(); return 3; },
            },
            context);

        Assert.Equal([1, 2, 3], results);
    }

    [Fact]
    public async Task CallBackendsInParallelAsync_OneFails_CancelsSiblingsAndThrows()
    {
        // The first failure must trigger linkedCts.Cancel() so siblings observing
        // the linked token can short-circuit. Without that, slow siblings keep
        // burning backend connections after the result is already lost.
        var context = TestFixtures.CreateTransformerContext(
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        var siblingTokenObserved = new TaskCompletionSource<CancellationToken>();

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await sut.CallBackendsInParallelForTest<int>(
                new Func<CancellationToken, Task<int>>[]
                {
                    async ct =>
                    {
                        await Task.Delay(10, ct);
                        throw new InvalidOperationException("boom");
                    },
                    async ct =>
                    {
                        // Capture the linked token so we can inspect cancellation
                        // after the strict-mode failure cascade has finished.
                        siblingTokenObserved.TrySetResult(ct);
                        try { await Task.Delay(30_000, ct); return 99; }
                        catch (OperationCanceledException) { throw; }
                    },
                },
                context);
        });

        // The catch block in CallBackendsInParallelAsync calls linkedCts.Cancel() then
        // awaits Task.WhenAll(tasks) before rethrowing. By the time ThrowsAsync returns,
        // cancellation must have propagated and the sibling's token must reflect it.
        var siblingToken = await siblingTokenObserved.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.True(siblingToken.IsCancellationRequested);
    }

    [Fact]
    public async Task CallBackendsInParallelAsync_HonoursOuterCancellationToken()
    {
        // The linked CTS combines context.CancellationToken with the failure-cancel,
        // so an outer cancel propagates into every call.
        using var outerCts = new CancellationTokenSource();
        var context = TestFixtures.CreateTransformerContext(cancellationToken: outerCts.Token);
        var sut = new ExposedMultiBackend();

        var ready = new TaskCompletionSource();

        var task = sut.CallBackendsInParallelForTest<int>(
            new Func<CancellationToken, Task<int>>[]
            {
                async ct =>
                {
                    ready.TrySetResult();
                    await Task.Delay(30_000, ct);
                    return 1;
                },
            },
            context);

        await ready.Task;
        outerCts.Cancel();

        // Either TaskCanceledException or OperationCanceledException is fine; both
        // signal that outer cancellation propagated through the linked token.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
    }

    // -----------------------------
    // CallBackendsInParallelSafeAsync (lenient, returns null per failure)
    // -----------------------------

    [Fact]
    public async Task CallBackendsInParallelSafeAsync_PartialFailure_ReturnsNullForFailed_SurvivorsKeepRunning()
    {
        // In the lenient variant, an exception in one call must not poison the others.
        // The failure becomes a null slot in the output array, in original order.
        var context = TestFixtures.CreateTransformerContext(
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        var results = await sut.CallBackendsInParallelSafeForTest<UserInfo>(
            new Func<CancellationToken, Task<UserInfo?>>[]
            {
                async ct => { await Task.Yield(); return new UserInfo { Id = "u1" }; },
                async ct => { await Task.Yield(); throw new InvalidOperationException("boom"); },
                async ct => { await Task.Yield(); return new UserInfo { Id = "u3" }; },
            },
            context);

        Assert.Equal(3, results.Length);
        Assert.Equal("u1", results[0]!.Id);
        Assert.Null(results[1]);
        Assert.Equal("u3", results[2]!.Id);
    }

    [Fact]
    public async Task CallBackendsInParallelSafeAsync_RequestCancelled_PropagatesInsteadOfAllNulls()
    {
        // A genuine request cancellation must NOT be swallowed into an all-nulls "success".
        // It propagates so the aggregation aborts - aligning the lenient variant with the strict
        // one, AggregatingTransformer, and BackendCaller.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var context = TestFixtures.CreateTransformerContext(cancellationToken: cts.Token);
        var sut = new ExposedMultiBackend();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sut.CallBackendsInParallelSafeForTest<UserInfo>(
                new Func<CancellationToken, Task<UserInfo?>>[]
                {
                    async ct => { ct.ThrowIfCancellationRequested(); await Task.Yield(); return new UserInfo(); },
                    async ct => { ct.ThrowIfCancellationRequested(); await Task.Yield(); return new UserInfo(); },
                },
                context));
    }

    [Fact]
    public async Task CallBackendsInParallelSafeAsync_AllFail_ReturnsAllNullsWithoutThrowing()
    {
        var context = TestFixtures.CreateTransformerContext(
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        var results = await sut.CallBackendsInParallelSafeForTest<UserInfo>(
            new Func<CancellationToken, Task<UserInfo?>>[]
            {
                _ => throw new InvalidOperationException("a"),
                _ => throw new InvalidOperationException("b"),
            },
            context);

        Assert.Equal(2, results.Length);
        Assert.All(results, Assert.Null);
    }

    [Fact]
    public async Task CallBackendsInParallelSafeAsync_OneFailureDoesNotCancelOuterToken()
    {
        // Distinct from the strict variant: a failure must NOT cancel siblings. The
        // outer context.CancellationToken is forwarded as-is so partial success is possible.
        var context = TestFixtures.CreateTransformerContext(
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        var siblingCompleted = new TaskCompletionSource<bool>();

        var results = await sut.CallBackendsInParallelSafeForTest<UserInfo>(
            new Func<CancellationToken, Task<UserInfo?>>[]
            {
                _ => throw new InvalidOperationException("fail fast"),
                async ct =>
                {
                    // Short delay - if outer cancellation propagated, this would throw OCE
                    // and the lenient handler would log + return null. We assert success below.
                    await Task.Delay(50, ct);
                    siblingCompleted.TrySetResult(true);
                    return new UserInfo { Id = "survivor" };
                },
            },
            context);

        Assert.True(await siblingCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
        Assert.Null(results[0]);
        Assert.Equal("survivor", results[1]!.Id);
    }

    [Fact]
    public async Task CallBackendsInParallelSafeAsync_Failure_LogsExceptionTypeOnly_NotMessage()
    {
        // The lenient variant must match the strict variant's secret-handling discipline:
        // backend exception messages can carry URLs/secrets, so only the exception TYPE is
        // logged - never the message (which here embeds a fake secret).
        var logger = new CapturingLogger();
        var context = TestFixtures.CreateTransformerContext(
            logger: logger,
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        var results = await sut.CallBackendsInParallelSafeForTest<UserInfo>(
            new Func<CancellationToken, Task<UserInfo?>>[]
            {
                _ => throw new InvalidOperationException("https://idp.example/secret-token=abc123"),
            },
            context);

        Assert.Single(results);
        Assert.Null(results[0]);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains(nameof(InvalidOperationException), entry.Message);
        Assert.DoesNotContain("secret-token", entry.Message);
        Assert.DoesNotContain("abc123", entry.Message);
    }

    // -----------------------------
    // CallSpecificBackendAsync
    // -----------------------------

    [Fact]
    public async Task CallSpecificBackendAsync_NoBody_BuildsBackendRequestFromArgs()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://other-svc/api/data", new UserInfo { Id = "u1" });
        var context = TestFixtures.CreateTransformerContext(
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        var result = await sut.CallSpecificBackendForTest<UserInfo>(
            method: "GET",
            url: "http://other-svc/api/data",
            context: context);

        Assert.True(result.IsSuccess);
        Assert.Equal("GET", backend.LastCall!.Request.Method);
        Assert.Equal("http://other-svc/api/data", backend.LastCall.Request.Url);
        Assert.Null(backend.LastCall.Body);
        Assert.False(backend.LastCall.Request.UseTokenExchange);
    }

    [Fact]
    public async Task CallSpecificBackendAsync_WithBody_SerializesAndForwards()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://other-svc/api/data", new UserInfo { Id = "u1" });
        var context = TestFixtures.CreateTransformerContext(
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        var body = new UserLookup { UserId = "u1" };
        await sut.CallSpecificBackendForTest<UserLookup, UserInfo>(
            method: "POST",
            url: "http://other-svc/api/data",
            body: body,
            context: context);

        Assert.Same(body, backend.LastCall!.GetBody<UserLookup>());
        Assert.Equal("POST", backend.LastCall.Request.Method);
    }

    [Fact]
    public async Task CallSpecificBackendAsync_PropagatesTokenExchangeArgs()
    {
        // Token-exchange args land on the synthesized BackendRequest. The auth handler
        // registry is downstream of this method; we only assert the request shape.
        var backend = new MockBackendCaller()
            .SetupResponse("http://order-svc/orders", new UserInfo { Id = "u1" });
        var context = TestFixtures.CreateTransformerContext(
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        await sut.CallSpecificBackendForTest<UserInfo>(
            method: "GET",
            url: "http://order-svc/orders",
            context: context,
            useTokenExchange: true,
            audience: "order-api");

        Assert.True(backend.LastCall!.Request.UseTokenExchange);
        Assert.Equal("order-api", backend.LastCall.Request.TokenExchangeAudience);
    }

    [Fact]
    public async Task CallSpecificBackendAsync_ForwardsProvidedToken_NotContextToken()
    {
        // Mirror of CallNamedBackendAsync_ForwardsProvidedToken_NotContextToken for the
        // specific-URL path: the context token stays alive and only the explicitly-passed
        // token is cancelled, so the call cancels ONLY if the provided token was forwarded.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var backend = new MockBackendCaller()
            .WithDelay(50)
            .SetupResponse("http://order-svc/orders", new UserInfo { Id = "u1" });
        var context = TestFixtures.CreateTransformerContext(
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sut.CallSpecificBackendForTest<UserInfo>(
                method: "GET",
                url: "http://order-svc/orders",
                context: context,
                cancellationToken: cts.Token));
    }

    // -----------------------------
    // MultiBackendTransformer<TRequest, TResponse> body-bearing variant
    // -----------------------------

    [Fact]
    public async Task BodyBearing_GetNamedBackends_Throws_WhenMissing()
    {
        var context = TestFixtures.CreateTransformerContext(
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackendWithBody();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => sut.CallNamedBackendForTest<UserInfo>("UserInfo", context));

        Assert.Contains("ToBackends()", ex.Message);
    }

    [Fact]
    public async Task CallNamedBackendAsync_ForwardsProvidedToken_NotContextToken()
    {
        // The headline cancellation feature: a token handed to the helper must reach the backend
        // call. Here the context token stays alive and only the explicitly-passed token is
        // cancelled - so the call cancels ONLY if the provided token was actually forwarded.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var backend = new MockBackendCaller()
            .WithDelay(50)
            .SetupResponse("http://user-service/api/users", new UserInfo { Id = "u1" });
        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "GET", "http://user-service/api/users", null));
        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackend();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sut.CallNamedBackendForTest<UserInfo>("UserInfo", context, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task BodyBearing_CallNamedBackendAsync_DispatchesAndRecordsBody()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://user-service/api/users", new UserInfo { Id = "u1" });
        var namedBackends = TestFixtures.CreateNamedBackends(
            ("UserInfo", "POST", "http://user-service/api/users", null));
        var context = TestFixtures.CreateTransformerContextWithNamedBackends(
            namedBackends,
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);

        var sut = new ExposedMultiBackendWithBody();
        var body = new UserLookup { UserId = "u1" };
        var result = await sut.CallNamedBackendForTest<UserLookup, UserInfo>("UserInfo", body, context);

        Assert.True(result.IsSuccess);
        Assert.Same(body, backend.LastCall!.GetBody<UserLookup>());
    }

    [Fact]
    public async Task BodyBearing_CallBackendsInParallelAsync_CancelsSiblingsOnFailure()
    {
        var context = TestFixtures.CreateTransformerContext(
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackendWithBody();

        var siblingTokenObserved = new TaskCompletionSource<CancellationToken>();

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await sut.CallBackendsInParallelForTest<int>(
                new Func<CancellationToken, Task<int>>[]
                {
                    async ct =>
                    {
                        await Task.Delay(10, ct);
                        throw new InvalidOperationException("boom");
                    },
                    async ct =>
                    {
                        siblingTokenObserved.TrySetResult(ct);
                        try { await Task.Delay(30_000, ct); return 1; }
                        catch (OperationCanceledException) { throw; }
                    },
                },
                context);
        });

        var siblingToken = await siblingTokenObserved.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.True(siblingToken.IsCancellationRequested);
    }

    [Fact]
    public async Task BodyBearing_CallBackendsInParallelSafeAsync_SwallowsIndividualFailures()
    {
        var context = TestFixtures.CreateTransformerContext(
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackendWithBody();

        var results = await sut.CallBackendsInParallelSafeForTest<UserInfo>(
            new Func<CancellationToken, Task<UserInfo?>>[]
            {
                _ => throw new InvalidOperationException("a"),
                async ct => { await Task.Yield(); return new UserInfo { Id = "ok" }; },
            },
            context);

        Assert.Null(results[0]);
        Assert.Equal("ok", results[1]!.Id);
    }

    [Fact]
    public async Task BodyBearing_CallSpecificBackendAsync_BuildsCorrectRequest()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://other-svc/api/data", new UserInfo { Id = "u1" });
        var context = TestFixtures.CreateTransformerContext(
            backendCaller: backend,
            cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedMultiBackendWithBody();

        var body = new UserLookup { UserId = "u1" };
        await sut.CallSpecificBackendForTest<UserLookup, UserInfo>(
            method: "POST",
            url: "http://other-svc/api/data",
            body: body,
            context: context,
            useTokenExchange: true,
            audience: "data-api");

        Assert.Same(body, backend.LastCall!.GetBody<UserLookup>());
        Assert.True(backend.LastCall.Request.UseTokenExchange);
        Assert.Equal("data-api", backend.LastCall.Request.TokenExchangeAudience);
    }

    // -----------------------------
    // Test doubles
    // -----------------------------

    /// <summary>Exposes the protected helpers of MultiBackendTransformer&lt;TResponse&gt;.</summary>
    private sealed class ExposedMultiBackend : MultiBackendTransformer<UserInfo>
    {
        public override Task<UserInfo> TransformAsync(TransformerContext context) => Task.FromResult(new UserInfo());

        public Task<BackendResult<TBackendResponse>> CallNamedBackendForTest<TBackendResponse>(
            string endpointName,
            TransformerContext context,
            IReadOnlyDictionary<string, object?>? routeValues = null,
            CancellationToken? cancellationToken = null)
            => CallNamedBackendAsync<TBackendResponse>(endpointName, context, routeValues, cancellationToken);

        public Task<BackendResult<TBackendResponse>> CallNamedBackendForTest<TBackendRequest, TBackendResponse>(
            string endpointName,
            TBackendRequest? body,
            TransformerContext context,
            IReadOnlyDictionary<string, object?>? routeValues = null)
            => CallNamedBackendAsync<TBackendRequest, TBackendResponse>(endpointName, body, context, routeValues);

        public Task<TResult[]> CallBackendsInParallelForTest<TResult>(
            IEnumerable<Func<CancellationToken, Task<TResult>>> calls,
            TransformerContext context)
            => CallBackendsInParallelAsync(calls, context);

        public Task<TResult?[]> CallBackendsInParallelSafeForTest<TResult>(
            IEnumerable<Func<CancellationToken, Task<TResult?>>> calls,
            TransformerContext context) where TResult : class
            => CallBackendsInParallelSafeAsync(calls, context);

        public Task<BackendResult<TBackendResponse>> CallSpecificBackendForTest<TBackendResponse>(
            string method,
            string url,
            TransformerContext context,
            bool useTokenExchange = false,
            string? audience = null,
            CancellationToken? cancellationToken = null)
            => CallSpecificBackendAsync<TBackendResponse>(method, url, context, useTokenExchange, audience, cancellationToken);

        public Task<BackendResult<TBackendResponse>> CallSpecificBackendForTest<TBackendRequest, TBackendResponse>(
            string method,
            string url,
            TBackendRequest? body,
            TransformerContext context,
            bool useTokenExchange = false,
            string? audience = null)
            => CallSpecificBackendAsync<TBackendRequest, TBackendResponse>(method, url, body, context, useTokenExchange, audience);
    }

    /// <summary>Exposes the protected helpers of MultiBackendTransformer&lt;TRequest, TResponse&gt; (the body-bearing twin).</summary>
    private sealed class ExposedMultiBackendWithBody : MultiBackendTransformer<UserLookup, UserInfo>
    {
        public override Task<UserInfo> TransformAsync(UserLookup? request, TransformerContext context)
            => Task.FromResult(new UserInfo());

        public Task<BackendResult<TBackendResponse>> CallNamedBackendForTest<TBackendResponse>(
            string endpointName,
            TransformerContext context,
            IReadOnlyDictionary<string, object?>? routeValues = null,
            CancellationToken? cancellationToken = null)
            => CallNamedBackendAsync<TBackendResponse>(endpointName, context, routeValues, cancellationToken);

        public Task<BackendResult<TBackendResponse>> CallNamedBackendForTest<TBackendRequest, TBackendResponse>(
            string endpointName,
            TBackendRequest? body,
            TransformerContext context,
            IReadOnlyDictionary<string, object?>? routeValues = null)
            => CallNamedBackendAsync<TBackendRequest, TBackendResponse>(endpointName, body, context, routeValues);

        public Task<TResult[]> CallBackendsInParallelForTest<TResult>(
            IEnumerable<Func<CancellationToken, Task<TResult>>> calls,
            TransformerContext context)
            => CallBackendsInParallelAsync(calls, context);

        public Task<TResult?[]> CallBackendsInParallelSafeForTest<TResult>(
            IEnumerable<Func<CancellationToken, Task<TResult?>>> calls,
            TransformerContext context) where TResult : class
            => CallBackendsInParallelSafeAsync(calls, context);

        public Task<BackendResult<TBackendResponse>> CallSpecificBackendForTest<TBackendRequest, TBackendResponse>(
            string method,
            string url,
            TBackendRequest? body,
            TransformerContext context,
            bool useTokenExchange = false,
            string? audience = null)
            => CallSpecificBackendAsync<TBackendRequest, TBackendResponse>(method, url, body, context, useTokenExchange, audience);
    }

    private sealed class UserInfo
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
    }

    private sealed class UserLookup
    {
        public string UserId { get; set; } = "";
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
