namespace b17s.Porta.Transformers;

/// <summary>
/// Base class for transformers that combine results from multiple backend services.
/// Supports parallel and sequential execution patterns.
/// Backend URLs are configured via ToBackends() in endpoint registration, not hardcoded.
/// </summary>
/// <remarks>
/// <para>
/// <b>IMPORTANT: Parallel Execution for Performance</b>
/// </para>
/// <para>
/// When calling multiple backends, always use <see cref="CallBackendsInParallelAsync{TResult}"/> or
/// <see cref="CallBackendsInParallelSafeAsync{TResult}"/> to execute calls concurrently.
/// Sequential awaits block the thread and significantly increase response latency.
/// </para>
/// <para>
/// <b>❌ BAD - Sequential execution (blocks unnecessarily):</b>
/// <code>
/// var userResult = await CallNamedBackendAsync&lt;UserInfo&gt;("UserInfo", context);
/// var productResult = await CallNamedBackendAsync&lt;ProductInfo&gt;("ProductInfo", context);
/// // Total time: userCall + productCall (e.g., 100ms + 100ms = 200ms)
/// </code>
/// </para>
/// <para>
/// <b>✅ GOOD - Parallel execution (forward <c>ct</c> so a sibling failure aborts in-flight calls):</b>
/// <code>
/// var results = await CallBackendsInParallelSafeAsync&lt;object&gt;([
///     async ct => (await CallNamedBackendAsync&lt;UserInfo&gt;("UserInfo", context, cancellationToken: ct)).Value,
///     async ct => (await CallNamedBackendAsync&lt;ProductInfo&gt;("ProductInfo", context, cancellationToken: ct)).Value
/// ], context);
/// // Total time: max(userCall, productCall) (e.g., max(100ms, 100ms) = 100ms)
/// </code>
/// </para>
/// <para>
/// Use sequential execution only when there are true data dependencies between calls
/// (e.g., the second call needs data from the first call's response).
/// </para>
/// </remarks>
/// <typeparam name="TRequest">The incoming request type</typeparam>
/// <typeparam name="TResponse">The aggregated response type</typeparam>
public abstract class MultiBackendTransformer<TRequest, TResponse> : TransformerBase<TRequest, TResponse>
{
    /// <summary>
    /// Gets the named backend endpoints configured for this transformer.
    /// </summary>
    /// <param name="context">The transformer context</param>
    /// <returns>The configured named backends</returns>
    /// <exception cref="InvalidOperationException">Thrown when no backends are configured</exception>
    protected NamedBackendEndpoints GetNamedBackends(TransformerContext context)
        => MultiBackendCalls.GetNamedBackends(context);

    /// <summary>
    /// Calls a named backend endpoint configured via ToBackends().
    /// </summary>
    /// <typeparam name="TBackendRequest">The backend request type</typeparam>
    /// <typeparam name="TBackendResponse">The backend response type</typeparam>
    /// <param name="endpointName">The name of the backend endpoint (as configured in ToBackends)</param>
    /// <param name="body">Request body (null for GET/DELETE)</param>
    /// <param name="context">The transformer context</param>
    /// <param name="routeValues">Optional additional route values for URL interpolation</param>
    /// <param name="cancellationToken">
    /// Optional cancellation token; defaults to <c>context.CancellationToken</c> when null. Forward the
    /// token a <see cref="CallBackendsInParallelAsync{TResult}"/> call passes you so a sibling failure
    /// actually aborts this in-flight backend request - otherwise the call ignores that cancellation.
    /// </param>
    /// <returns>The backend result</returns>
    protected Task<BackendResult<TBackendResponse>> CallNamedBackendAsync<TBackendRequest, TBackendResponse>(
        string endpointName,
        TBackendRequest? body,
        TransformerContext context,
        IReadOnlyDictionary<string, object?>? routeValues = null,
        CancellationToken? cancellationToken = null)
        => MultiBackendCalls.CallNamedBackendAsync<TBackendRequest, TBackendResponse>(
            endpointName, body, context, routeValues, cancellationToken);

    /// <summary>
    /// Calls a named backend endpoint (GET request - no body).
    /// </summary>
    protected Task<BackendResult<TBackendResponse>> CallNamedBackendAsync<TBackendResponse>(
        string endpointName,
        TransformerContext context,
        IReadOnlyDictionary<string, object?>? routeValues = null,
        CancellationToken? cancellationToken = null)
        => CallNamedBackendAsync<object, TBackendResponse>(endpointName, body: null, context, routeValues, cancellationToken);

    /// <summary>
    /// Calls multiple backends in parallel and waits for all to complete.
    /// All tasks are started immediately and executed concurrently using Task.WhenAll.
    /// </summary>
    /// <param name="calls">
    /// The backend calls to execute - all will be started immediately. Each call receives a
    /// linked <see cref="CancellationToken"/> that is cancelled as soon as any sibling call
    /// fails; forward it (e.g. <c>CallNamedBackendAsync(..., cancellationToken: ct)</c>) so
    /// in-flight backend requests are aborted on first failure.
    /// </param>
    /// <param name="context">The transformer context</param>
    /// <returns>Array of results in the same order as the calls</returns>
    /// <remarks>
    /// <para>
    /// This method starts all backend calls simultaneously. The total execution time
    /// equals the slowest call, not the sum of all calls.
    /// </para>
    /// <para>
    /// Use this when all calls must succeed. If any call fails, the linked token is cancelled
    /// so siblings can stop early instead of running to completion in the background.
    /// For partial failure tolerance, use <see cref="CallBackendsInParallelSafeAsync{TResult}"/> instead.
    /// </para>
    /// </remarks>
    /// <exception cref="Exception">Throws if any backend call fails</exception>
    protected Task<TResult[]> CallBackendsInParallelAsync<TResult>(
        IEnumerable<Func<CancellationToken, Task<TResult>>> calls,
        TransformerContext context)
        => MultiBackendCalls.CallBackendsInParallelAsync(calls, context);

    /// <summary>
    /// Calls multiple backends in parallel with individual error handling.
    /// Failed calls return null instead of throwing, allowing partial success scenarios.
    /// All tasks are started immediately and executed concurrently using Task.WhenAll.
    /// </summary>
    /// <param name="calls">
    /// The backend calls to execute - all will be started immediately. Each call receives the
    /// request's <see cref="CancellationToken"/>; this overload does <i>not</i> cancel siblings
    /// on individual failures because partial success is the goal. A genuine request cancellation
    /// (client disconnect / fired deadline) is <i>not</i> swallowed - it aborts the whole aggregation.
    /// </param>
    /// <param name="context">The transformer context</param>
    /// <returns>Array of results (null for failed calls) in the same order as the calls</returns>
    /// <remarks>
    /// <para>
    /// Use this for imperative partial-success aggregation. Note two trade-offs versus the
    /// declarative <c>AggregatingTransformer</c>: the examples funnel results through
    /// <c>object?[]</c> + <c>as</c> casts (a wrong type argument reads as <c>null</c>, the same as a
    /// failed call), and a failure collapses to a bare <c>null</c> with no way to tell "backend threw"
    /// from "backend returned null". When you need typed access or that distinction, prefer
    /// <c>AggregatingTransformer</c> with its typed <c>Get&lt;T&gt;(name)</c> and <c>BackendCallOutcome</c>.
    /// </para>
    /// <para>
    /// Example:
    /// <code>
    /// var results = await CallBackendsInParallelSafeAsync&lt;object&gt;([
    ///     async ct => (await CallNamedBackendAsync&lt;UserInfo&gt;("UserInfo", context, cancellationToken: ct)).Value,
    ///     async ct => (await CallNamedBackendAsync&lt;ProductInfo&gt;("ProductInfo", context, cancellationToken: ct)).Value
    /// ], context);
    ///
    /// var userInfo = results[0] as UserInfo;      // null if call failed
    /// var productInfo = results[1] as ProductInfo; // null if call failed
    /// </code>
    /// </para>
    /// </remarks>
    protected Task<TResult?[]> CallBackendsInParallelSafeAsync<TResult>(
        IEnumerable<Func<CancellationToken, Task<TResult?>>> calls,
        TransformerContext context) where TResult : class
    {
        InitializeLogger(context);
        return MultiBackendCalls.CallBackendsInParallelSafeAsync(calls, context);
    }

    /// <summary>
    /// Calls a specific backend service.
    /// </summary>
    /// <typeparam name="TBackendRequest">The backend request type</typeparam>
    /// <typeparam name="TBackendResponse">The backend response type</typeparam>
    /// <param name="method">HTTP method</param>
    /// <param name="url">Backend URL (supports Kubernetes service names)</param>
    /// <param name="body">Request body (null for GET/DELETE)</param>
    /// <param name="context">The transformer context</param>
    /// <param name="useTokenExchange">Whether to use token exchange</param>
    /// <param name="audience">Target audience for token exchange</param>
    /// <param name="cancellationToken">
    /// Optional cancellation token; defaults to <c>context.CancellationToken</c> when null. Forward the
    /// token a <see cref="CallBackendsInParallelAsync{TResult}"/> call passes you so a sibling failure
    /// actually aborts this in-flight backend request.
    /// </param>
    /// <returns>The backend result</returns>
    protected Task<BackendResult<TBackendResponse>> CallSpecificBackendAsync<TBackendRequest, TBackendResponse>(
        string method,
        string url,
        TBackendRequest? body,
        TransformerContext context,
        bool useTokenExchange = false,
        string? audience = null,
        CancellationToken? cancellationToken = null)
        => MultiBackendCalls.CallSpecificBackendAsync<TBackendRequest, TBackendResponse>(
            method, url, body, context, useTokenExchange, audience, cancellationToken);

    /// <summary>
    /// Calls a specific backend service (GET request - no body).
    /// </summary>
    protected Task<BackendResult<TBackendResponse>> CallSpecificBackendAsync<TBackendResponse>(
        string method,
        string url,
        TransformerContext context,
        bool useTokenExchange = false,
        string? audience = null,
        CancellationToken? cancellationToken = null)
        => CallSpecificBackendAsync<object, TBackendResponse>(method, url, body: null, context, useTokenExchange, audience, cancellationToken);
}

/// <summary>
/// Base class for transformers that combine results from multiple backend services.
/// Supports parallel and sequential execution patterns.
/// Backend URLs are configured via ToBackends() in endpoint registration, not hardcoded.
/// </summary>
/// <remarks>
/// <para>
/// <b>IMPORTANT: Parallel Execution for Performance</b>
/// </para>
/// <para>
/// When calling multiple backends, always use <see cref="CallBackendsInParallelAsync{TResult}"/> or
/// <see cref="CallBackendsInParallelSafeAsync{TResult}"/> to execute calls concurrently.
/// Sequential awaits block the thread and significantly increase response latency.
/// </para>
/// <para>
/// <b>❌ BAD - Sequential execution (blocks unnecessarily):</b>
/// <code>
/// var userResult = await CallNamedBackendAsync&lt;UserInfo&gt;("UserInfo", context);
/// var productResult = await CallNamedBackendAsync&lt;ProductInfo&gt;("ProductInfo", context);
/// // Total time: userCall + productCall (e.g., 100ms + 100ms = 200ms)
/// </code>
/// </para>
/// <para>
/// <b>✅ GOOD - Parallel execution (forward <c>ct</c> so a sibling failure aborts in-flight calls):</b>
/// <code>
/// var results = await CallBackendsInParallelSafeAsync&lt;object&gt;([
///     async ct => (await CallNamedBackendAsync&lt;UserInfo&gt;("UserInfo", context, cancellationToken: ct)).Value,
///     async ct => (await CallNamedBackendAsync&lt;ProductInfo&gt;("ProductInfo", context, cancellationToken: ct)).Value
/// ], context);
/// // Total time: max(userCall, productCall) (e.g., max(100ms, 100ms) = 100ms)
/// </code>
/// </para>
/// <para>
/// Use sequential execution only when there are true data dependencies between calls
/// (e.g., the second call needs data from the first call's response).
/// </para>
/// </remarks>
/// <typeparam name="TResponse">The aggregated response type</typeparam>
public abstract class MultiBackendTransformer<TResponse> : TransformerBase<TResponse>
{
    /// <summary>
    /// Gets the named backend endpoints configured for this transformer.
    /// </summary>
    /// <param name="context">The transformer context</param>
    /// <returns>The configured named backends</returns>
    /// <exception cref="InvalidOperationException">Thrown when no backends are configured</exception>
    protected NamedBackendEndpoints GetNamedBackends(TransformerContext context)
        => MultiBackendCalls.GetNamedBackends(context);

    /// <summary>
    /// Calls a named backend endpoint configured via ToBackends().
    /// </summary>
    /// <typeparam name="TBackendRequest">The backend request type</typeparam>
    /// <typeparam name="TBackendResponse">The backend response type</typeparam>
    /// <param name="endpointName">The name of the backend endpoint (as configured in ToBackends)</param>
    /// <param name="body">Request body (null for GET/DELETE)</param>
    /// <param name="context">The transformer context</param>
    /// <param name="routeValues">Optional additional route values for URL interpolation</param>
    /// <param name="cancellationToken">
    /// Optional cancellation token; defaults to <c>context.CancellationToken</c> when null. Forward the
    /// token a <see cref="CallBackendsInParallelAsync{TResult}"/> call passes you so a sibling failure
    /// actually aborts this in-flight backend request - otherwise the call ignores that cancellation.
    /// </param>
    /// <returns>The backend result</returns>
    protected Task<BackendResult<TBackendResponse>> CallNamedBackendAsync<TBackendRequest, TBackendResponse>(
        string endpointName,
        TBackendRequest? body,
        TransformerContext context,
        IReadOnlyDictionary<string, object?>? routeValues = null,
        CancellationToken? cancellationToken = null)
        => MultiBackendCalls.CallNamedBackendAsync<TBackendRequest, TBackendResponse>(
            endpointName, body, context, routeValues, cancellationToken);

    /// <summary>
    /// Calls a named backend endpoint (GET request - no body).
    /// </summary>
    protected Task<BackendResult<TBackendResponse>> CallNamedBackendAsync<TBackendResponse>(
        string endpointName,
        TransformerContext context,
        IReadOnlyDictionary<string, object?>? routeValues = null,
        CancellationToken? cancellationToken = null)
        => CallNamedBackendAsync<object, TBackendResponse>(endpointName, body: null, context, routeValues, cancellationToken);

    /// <summary>
    /// Calls multiple backends in parallel and waits for all to complete.
    /// All tasks are started immediately and executed concurrently using Task.WhenAll.
    /// </summary>
    /// <param name="calls">
    /// The backend calls to execute - all will be started immediately. Each call receives a
    /// linked <see cref="CancellationToken"/> that is cancelled as soon as any sibling call
    /// fails; forward it (e.g. <c>CallNamedBackendAsync(..., cancellationToken: ct)</c>) so
    /// in-flight backend requests are aborted on first failure.
    /// </param>
    /// <param name="context">The transformer context</param>
    /// <returns>Array of results in the same order as the calls</returns>
    /// <remarks>
    /// <para>
    /// This method starts all backend calls simultaneously. The total execution time
    /// equals the slowest call, not the sum of all calls.
    /// </para>
    /// <para>
    /// Use this when all calls must succeed. If any call fails, the linked token is cancelled
    /// so siblings can stop early instead of running to completion in the background.
    /// For partial failure tolerance, use <see cref="CallBackendsInParallelSafeAsync{TResult}"/> instead.
    /// </para>
    /// </remarks>
    /// <exception cref="Exception">Throws if any backend call fails</exception>
    protected Task<TResult[]> CallBackendsInParallelAsync<TResult>(
        IEnumerable<Func<CancellationToken, Task<TResult>>> calls,
        TransformerContext context)
        => MultiBackendCalls.CallBackendsInParallelAsync(calls, context);

    /// <summary>
    /// Calls multiple backends in parallel with individual error handling.
    /// Failed calls return null instead of throwing, allowing partial success scenarios.
    /// All tasks are started immediately and executed concurrently using Task.WhenAll.
    /// </summary>
    /// <param name="calls">
    /// The backend calls to execute - all will be started immediately. Each call receives the
    /// request's <see cref="CancellationToken"/>; this overload does <i>not</i> cancel siblings
    /// on individual failures because partial success is the goal. A genuine request cancellation
    /// (client disconnect / fired deadline) is <i>not</i> swallowed - it aborts the whole aggregation.
    /// </param>
    /// <param name="context">The transformer context</param>
    /// <returns>Array of results (null for failed calls) in the same order as the calls</returns>
    /// <remarks>
    /// <para>
    /// Use this for imperative partial-success aggregation. Note two trade-offs versus the
    /// declarative <c>AggregatingTransformer</c>: the examples funnel results through
    /// <c>object?[]</c> + <c>as</c> casts (a wrong type argument reads as <c>null</c>, the same as a
    /// failed call), and a failure collapses to a bare <c>null</c> with no way to tell "backend threw"
    /// from "backend returned null". When you need typed access or that distinction, prefer
    /// <c>AggregatingTransformer</c> with its typed <c>Get&lt;T&gt;(name)</c> and <c>BackendCallOutcome</c>.
    /// </para>
    /// <para>
    /// Example:
    /// <code>
    /// var results = await CallBackendsInParallelSafeAsync&lt;object&gt;([
    ///     async ct => (await CallNamedBackendAsync&lt;UserInfo&gt;("UserInfo", context, cancellationToken: ct)).Value,
    ///     async ct => (await CallNamedBackendAsync&lt;ProductInfo&gt;("ProductInfo", context, cancellationToken: ct)).Value
    /// ], context);
    ///
    /// var userInfo = results[0] as UserInfo;      // null if call failed
    /// var productInfo = results[1] as ProductInfo; // null if call failed
    /// </code>
    /// </para>
    /// </remarks>
    protected Task<TResult?[]> CallBackendsInParallelSafeAsync<TResult>(
        IEnumerable<Func<CancellationToken, Task<TResult?>>> calls,
        TransformerContext context) where TResult : class
    {
        InitializeLogger(context);
        return MultiBackendCalls.CallBackendsInParallelSafeAsync(calls, context);
    }

    /// <summary>
    /// Calls a specific backend service.
    /// </summary>
    /// <typeparam name="TBackendRequest">The backend request type</typeparam>
    /// <typeparam name="TBackendResponse">The backend response type</typeparam>
    /// <param name="method">HTTP method</param>
    /// <param name="url">Backend URL (supports Kubernetes service names)</param>
    /// <param name="body">Request body (null for GET/DELETE)</param>
    /// <param name="context">The transformer context</param>
    /// <param name="useTokenExchange">Whether to use token exchange</param>
    /// <param name="audience">Target audience for token exchange</param>
    /// <param name="cancellationToken">
    /// Optional cancellation token; defaults to <c>context.CancellationToken</c> when null. Forward the
    /// token a <see cref="CallBackendsInParallelAsync{TResult}"/> call passes you so a sibling failure
    /// actually aborts this in-flight backend request.
    /// </param>
    /// <returns>The backend result</returns>
    protected Task<BackendResult<TBackendResponse>> CallSpecificBackendAsync<TBackendRequest, TBackendResponse>(
        string method,
        string url,
        TBackendRequest? body,
        TransformerContext context,
        bool useTokenExchange = false,
        string? audience = null,
        CancellationToken? cancellationToken = null)
        => MultiBackendCalls.CallSpecificBackendAsync<TBackendRequest, TBackendResponse>(
            method, url, body, context, useTokenExchange, audience, cancellationToken);

    /// <summary>
    /// Calls a specific backend service (GET request - no body).
    /// </summary>
    protected Task<BackendResult<TBackendResponse>> CallSpecificBackendAsync<TBackendResponse>(
        string method,
        string url,
        TransformerContext context,
        bool useTokenExchange = false,
        string? audience = null,
        CancellationToken? cancellationToken = null)
        => CallSpecificBackendAsync<object, TBackendResponse>(method, url, body: null, context, useTokenExchange, audience, cancellationToken);
}

/// <summary>
/// Shared implementation of the multi-backend call helpers, used by both arities of
/// <c>MultiBackendTransformer</c> so the orchestration logic - and its fixes - live in one place
/// rather than being maintained as a verbatim copy in each base class.
/// </summary>
internal static class MultiBackendCalls
{
    public static NamedBackendEndpoints GetNamedBackends(TransformerContext context)
    {
        if (!context.Properties.TryGetValue("NamedBackends", out var value) ||
            value is not NamedBackendEndpoints namedBackends)
        {
            throw new InvalidOperationException(
                "No named backends configured. Use ToBackends() in the endpoint registration to configure backend URLs.");
        }
        return namedBackends;
    }

    public static async Task<BackendResult<TBackendResponse>> CallNamedBackendAsync<TBackendRequest, TBackendResponse>(
        string endpointName,
        TBackendRequest? body,
        TransformerContext context,
        IReadOnlyDictionary<string, object?>? routeValues,
        CancellationToken? cancellationToken)
    {
        // Honour an explicit token (e.g. the linked token from CallBackendsInParallelAsync) so a
        // sibling failure can abort this call; fall back to the request token when none is passed.
        var ct = cancellationToken ?? context.CancellationToken;

        var namedBackends = GetNamedBackends(context);
        var endpoint = namedBackends.Get(endpointName);

        // Merge route values from context with any additional route values
        var mergedRouteValues = routeValues != null
            ? context.RouteValues.Concat(routeValues.Where(kv => !context.RouteValues.ContainsKey(kv.Key)))
                .ToDictionary(kv => kv.Key, kv => kv.Value)
            : context.RouteValues;

        var backendRequest = endpoint.ToBackendRequest(mergedRouteValues, context.AuthContext.AccessToken);

        if (body == null)
        {
            return await context.BackendCaller.CallAsync<TBackendResponse>(backendRequest, ct);
        }

        return await context.BackendCaller.CallAsync<TBackendRequest, TBackendResponse>(backendRequest, body, ct);
    }

    public static async Task<TResult[]> CallBackendsInParallelAsync<TResult>(
        IEnumerable<Func<CancellationToken, Task<TResult>>> calls,
        TransformerContext context)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
        var tasks = calls.Select(call => call(linkedCts.Token)).ToArray();
        try
        {
            return await Task.WhenAll(tasks);
        }
        catch
        {
            // Cancel siblings on first failure so they stop burning backend connections
            // instead of running fire-and-forget. Then observe their completion to avoid
            // leaving unobserved exceptions on the finalizer thread.
            linkedCts.Cancel();
            try { await Task.WhenAll(tasks); }
            catch (Exception siblingEx)
            {
                // The first failure is rethrown below; this only drains sibling tasks to
                // avoid unobserved exceptions. Breadcrumb at Debug, type only (backend
                // exception messages can carry URLs/secrets).
                TransformerLogging.SiblingTaskFaultObserved(context.Logger, siblingEx.GetType().Name);
            }
            throw;
        }
    }

    public static async Task<TResult?[]> CallBackendsInParallelSafeAsync<TResult>(
        IEnumerable<Func<CancellationToken, Task<TResult?>>> calls,
        TransformerContext context) where TResult : class
    {
        var tasks = calls.Select(async call =>
        {
            try
            {
                return await call(context.CancellationToken);
            }
            catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
            {
                // A genuine request cancellation (client disconnect / fired deadline) is NOT a
                // per-call failure to mask as null - that would manufacture an all-nulls "success"
                // for a dead request. Propagate it so the whole aggregation aborts, matching the
                // strict variant, AggregatingTransformer, and BackendCaller.
                throw;
            }
            catch (Exception ex)
            {
                // Type only - the strict variant (SiblingTaskFaultObserved) logs type-only because
                // backend exception messages can carry URLs/secrets; match that here.
                TransformerLogging.BackendCallFailedSafe(context.Logger, ex.GetType().Name);
                return null;
            }
        }).ToArray();

        return await Task.WhenAll(tasks);
    }

    public static async Task<BackendResult<TBackendResponse>> CallSpecificBackendAsync<TBackendRequest, TBackendResponse>(
        string method,
        string url,
        TBackendRequest? body,
        TransformerContext context,
        bool useTokenExchange,
        string? audience,
        CancellationToken? cancellationToken)
    {
        var ct = cancellationToken ?? context.CancellationToken;

        var backendRequest = new BackendRequest
        {
            Method = method,
            Url = url,
            AccessToken = context.AuthContext.AccessToken,
            UseTokenExchange = useTokenExchange,
            TokenExchangeAudience = audience
        };

        if (body == null)
        {
            return await context.BackendCaller.CallAsync<TBackendResponse>(backendRequest, ct);
        }

        return await context.BackendCaller.CallAsync<TBackendRequest, TBackendResponse>(backendRequest, body, ct);
    }
}
