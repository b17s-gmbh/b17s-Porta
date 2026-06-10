using System.Collections.Concurrent;
using System.Diagnostics;

using b17s.Porta.Telemetry;

namespace b17s.Porta.Transformers;

/// <summary>
/// A declarative transformer for aggregating results from multiple backend services.
/// Uses a fluent configuration API to define backend calls and result mapping.
/// </summary>
/// <typeparam name="TResponse">The aggregated response type</typeparam>
/// <example>
/// public class EnrichedUserProfileTransformer : AggregatingTransformer&lt;EnrichedUserProfile&gt;
/// {
///     protected override void Configure(AggregatorBuilder builder)
///     {
///         builder.Backend&lt;UserInfo&gt;("UserInfo")
///             .WithBody(ctx =&gt; new BackendUserRequest { UserId = ctx.UserId! });
///
///         builder.Backend&lt;UserProductInfo&gt;("ProductInfo")
///             .WithBody(ctx =&gt; new BackendUserRequest { UserId = ctx.UserId! });
///     }
///
///     protected override EnrichedUserProfile MapResults(AggregatorResults results, TransformerContext context)
///     {
///         var userInfo = results.Get&lt;UserInfo&gt;("UserInfo");
///         var productInfo = results.Get&lt;UserProductInfo&gt;("ProductInfo");
///
///         return new EnrichedUserProfile
///         {
///             UserInfo = userInfo ?? new(),
///             ProductInfo = productInfo ?? new(),
///             IsFullyEnriched = userInfo != null &amp;&amp; productInfo != null
///         };
///     }
/// }
/// </example>
public abstract class AggregatingTransformer<TResponse> : MultiBackendTransformer<TResponse>
{
    private AggregatorBuilder? _builder;

    /// <summary>
    /// Configure the backend calls using the fluent builder API.
    /// </summary>
    protected abstract void Configure(AggregatorBuilder builder);

    /// <summary>
    /// Map the results from all backend calls to the final response.
    /// </summary>
    protected abstract TResponse MapResults(AggregatorResults results, TransformerContext context);

    private AggregatorBuilder GetOrCreateBuilder()
    {
        if (_builder == null)
        {
            _builder = new AggregatorBuilder();
            Configure(_builder);
        }
        return _builder;
    }

    /// <inheritdoc/>
    public override async Task<TResponse> TransformAsync(TransformerContext context)
    {
        InitializeLogger(context);
        var builder = GetOrCreateBuilder();

        // Execute all backend calls in parallel
        var results = new ConcurrentDictionary<string, object?>();
        var outcomes = new ConcurrentDictionary<string, BackendCallOutcome>();
        var backendConfigs = builder.GetBackendConfigs();
        var transformerName = GetType().Name;

        var tasks = backendConfigs.Select(async config =>
        {
            // Create child span for each backend call when telemetry is enabled. Fixed category
            // activity name (bff.backend); the aggregating transformer and the specific backend are
            // carried on tags (aggregator.transformer, bff.backend.service) so cardinality stays bounded.
            using var activity = context.TelemetryEnabled
                ? PortaActivitySource.Source.StartActivity(
                    PortaActivitySource.Activities.BackendCall,
                    ActivityKind.Internal)
                : null;

            activity?.SetTag(PortaActivitySource.Tags.Component, "aggregator");
            activity?.SetTag(PortaActivitySource.Tags.BackendService, config.Name);
            activity?.SetTag("aggregator.transformer", transformerName);

            try
            {
                var result = await ExecuteBackendCallAsync(config, context);
                results[config.Name] = result.Value;
                var outcome = !result.IsSuccess
                    ? BackendCallOutcome.Failed
                    : result.Value is null
                        ? BackendCallOutcome.ReturnedNull
                        : BackendCallOutcome.Success;
                outcomes[config.Name] = outcome;

                // Record outcome. Only a non-null Success is an Ok span; both "returned null"
                // and "backend failed" are Error. The description is null on success so we don't
                // tag healthy spans with a misleading message.
                var succeeded = outcome == BackendCallOutcome.Success;
                activity?.SetStatus(
                    succeeded ? ActivityStatusCode.Ok : ActivityStatusCode.Error,
                    succeeded ? null : outcome.ToString());
                activity?.SetTag("aggregator.success", succeeded);
                activity?.SetTag("aggregator.outcome", outcome.ToString());
            }
            catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
            {
                // Cancellation (client disconnect or a global request timeout) is not a backend
                // failure. Let it propagate so the request actually aborts, instead of recording
                // every in-flight leg as Threw, returning a 200 with mostly-null data, and
                // polluting backend error metrics with non-errors.
                throw;
            }
            catch (Exception ex)
            {
                LogBackendCallFailed(ex);
                results[config.Name] = null;
                outcomes[config.Name] = BackendCallOutcome.Threw;

                // Record failure - stack trace is recorded via AddException (event-scoped,
                // OTel semantic conventions) rather than as a high-cardinality span tag.
                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                activity?.SetTag(PortaActivitySource.Tags.ErrorType, ex.GetType().Name);
                activity?.SetTag(PortaActivitySource.Tags.ErrorMessage, ex.Message);
                activity?.AddException(ex);
                activity?.SetTag("aggregator.success", false);
                activity?.SetTag("aggregator.outcome", nameof(BackendCallOutcome.Threw));
            }
        }).ToArray();

        await Task.WhenAll(tasks);

        // Map results
        var aggregatorResults = new AggregatorResults(results, outcomes);
        return MapResults(aggregatorResults, context);
    }

    private async Task<BackendObjectResult> ExecuteBackendCallAsync(BackendCallConfig config, TransformerContext context)
    {
        var namedBackends = GetNamedBackends(context);
        var endpoint = namedBackends.Get(config.Name);

        // A per-backend WithRouteValues() factory supplies additional interpolation values for
        // this call. Merge them with the ambient context.RouteValues, matching the merge in
        // MultiBackendCalls.CallNamedBackendAsync: ambient values win on a key collision, the
        // factory only fills in keys the request didn't already provide.
        var additionalRouteValues = config.RouteValuesFactory?.Invoke(context);
        var routeValues = additionalRouteValues != null
            ? context.RouteValues
                .Concat(additionalRouteValues.Where(kv => !context.RouteValues.ContainsKey(kv.Key)))
                .ToDictionary(kv => kv.Key, kv => kv.Value)
            : context.RouteValues;

        var backendRequest = endpoint.ToBackendRequest(routeValues, context.AuthContext.AccessToken);

        // Return the raw result (success flag + value) so the caller can tell an unsuccessful
        // backend response (Failed) apart from a successful-but-empty payload (ReturnedNull).
        if (config.BodyFactory != null)
        {
            var body = config.BodyFactory(context);
            return await context.BackendCaller.CallWithBodyAsync(backendRequest, body, config.ResponseType, context.CancellationToken);
        }

        return await context.BackendCaller.CallAsync(backendRequest, config.ResponseType, context.CancellationToken);
    }
}

/// <summary>
/// Fluent builder for configuring backend calls in an aggregating transformer.
/// </summary>
public sealed class AggregatorBuilder
{
    private readonly List<BackendCallConfig> _backends = [];

    /// <summary>
    /// Configure a backend call that returns the specified type.
    /// The name must match a backend configured via ToBackends() in endpoint registration.
    /// </summary>
    public BackendCallBuilder<TBackendResponse> Backend<TBackendResponse>(string name)
    {
        var config = new BackendCallConfig(name, typeof(TBackendResponse));
        _backends.Add(config);
        return new BackendCallBuilder<TBackendResponse>(config);
    }

    internal IReadOnlyList<BackendCallConfig> GetBackendConfigs() => _backends;
}

/// <summary>
/// Fluent builder for configuring a single backend call.
/// </summary>
public sealed class BackendCallBuilder<TResponse>
{
    private readonly BackendCallConfig _config;

    internal BackendCallBuilder(BackendCallConfig config)
    {
        _config = config;
    }

    /// <summary>
    /// Specify a request body to send to the backend.
    /// </summary>
    public BackendCallBuilder<TResponse> WithBody<TRequest>(Func<TransformerContext, TRequest> bodyFactory)
    {
        _config.BodyFactory = ctx => bodyFactory(ctx)!;
        _config.RequestType = typeof(TRequest);
        return this;
    }

    /// <summary>
    /// Supply additional per-backend route values for URL interpolation. The factory is invoked
    /// with the <see cref="TransformerContext"/> when the backend call is made, and its values are
    /// merged with the request's ambient route values. On a key collision the ambient value wins -
    /// the factory only fills in keys the request didn't already provide, matching the merge
    /// semantics of the other multi-backend call paths.
    /// </summary>
    /// <param name="routeValuesFactory">
    /// Produces additional route values to interpolate into this backend's URL template. Return an
    /// empty dictionary to use only the ambient route values.
    /// </param>
    /// <returns>The builder, for chaining.</returns>
    public BackendCallBuilder<TResponse> WithRouteValues(Func<TransformerContext, IReadOnlyDictionary<string, object?>> routeValuesFactory)
    {
        _config.RouteValuesFactory = routeValuesFactory;
        return this;
    }
}

/// <summary>
/// Configuration for a single backend call.
/// </summary>
internal sealed class BackendCallConfig(string name, Type responseType)
{
    public string Name { get; } = name;
    public Type ResponseType { get; } = responseType;
    public Type? RequestType { get; set; }
    public Func<TransformerContext, object>? BodyFactory { get; set; }
    public Func<TransformerContext, IReadOnlyDictionary<string, object?>>? RouteValuesFactory { get; set; }
}

/// <summary>
/// Outcome of a single backend call inside an <see cref="AggregatingTransformer{TResponse}"/>.
/// Lets downstream `MapResults` distinguish "backend returned null" (call
/// completed, result was empty) from "backend threw" (call failed) - both of
/// which previously surfaced as a null value in the results dictionary.
/// </summary>
public enum BackendCallOutcome
{
    /// <summary>The call completed and returned a non-null value.</summary>
    Success,
    /// <summary>The call completed successfully but the backend produced a null payload (e.g. HTTP 200 with an empty body).</summary>
    ReturnedNull,
    /// <summary>The call threw an exception before producing a result.</summary>
    Threw,
    /// <summary>The call completed but the backend returned an unsuccessful response (e.g. HTTP 4xx/5xx). Distinct from <see cref="ReturnedNull"/>, which means "service has no data" rather than "service errored".</summary>
    Failed,
}

/// <summary>
/// Provides access to the results of backend calls.
/// </summary>
public sealed class AggregatorResults
{
    private readonly IReadOnlyDictionary<string, object?> _results;
    private readonly IReadOnlyDictionary<string, BackendCallOutcome> _outcomes;

    internal AggregatorResults(
        IReadOnlyDictionary<string, object?> results,
        IReadOnlyDictionary<string, BackendCallOutcome> outcomes)
    {
        _results = results;
        _outcomes = outcomes;
    }

    /// <summary>
    /// Get the result of a backend call by name.
    /// Returns null if the call failed or returned null.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The named call produced a non-null value whose runtime type is not assignable to
    /// <typeparamref name="T"/> - i.e. the type argument here disagrees with the
    /// <c>Backend&lt;T&gt;</c> registration. Surfaced rather than silently returning null so a
    /// type-parameter mistake is not mistaken for "the backend had no data".
    /// </exception>
    public T? Get<T>(string name) where T : class
    {
        if (!_results.TryGetValue(name, out var value) || value is null)
        {
            return null;
        }
        if (value is not T typed)
        {
            throw new InvalidOperationException(
                $"Backend result '{name}' is of type '{value.GetType().Name}', which is not assignable to '{typeof(T).Name}'. " +
                $"Ensure the type argument on Get<{typeof(T).Name}>(\"{name}\") matches the Backend<T>(\"{name}\") registration.");
        }
        return typed;
    }

    /// <summary>
    /// Get the result of a backend call by name, with a default value.
    /// </summary>
    public T GetOrDefault<T>(string name, T defaultValue) where T : class
        => Get<T>(name) ?? defaultValue;

    /// <summary>
    /// Check if a backend call succeeded (returned non-null result).
    /// </summary>
    public bool HasResult(string name)
        => _results.TryGetValue(name, out var value) && value != null;

    /// <summary>
    /// Check if all specified backend calls succeeded.
    /// </summary>
    public bool AllSucceeded(params string[] names)
        => names.All(HasResult);

    /// <summary>
    /// Get the count of successful results.
    /// </summary>
    public int SuccessCount => _results.Count(r => r.Value != null);

    /// <summary>
    /// Get all result names.
    /// </summary>
    public IEnumerable<string> Names => _results.Keys;

    /// <summary>
    /// Get the outcome of a backend call by name. Distinguishes "the call
    /// completed and produced a null payload" from "the call threw" - both of
    /// which return null from <see cref="Get{T}"/>.
    /// </summary>
    public BackendCallOutcome GetOutcome(string name)
        => _outcomes.TryGetValue(name, out var outcome) ? outcome : BackendCallOutcome.ReturnedNull;

    /// <summary>
    /// True if the named call threw an exception before producing a result.
    /// </summary>
    public bool Threw(string name) => GetOutcome(name) == BackendCallOutcome.Threw;

    /// <summary>
    /// True if the named call completed but the backend returned an unsuccessful response
    /// (e.g. HTTP 4xx/5xx). Distinct from a successful call that produced a null payload
    /// (<see cref="BackendCallOutcome.ReturnedNull"/>), letting callers degrade differently on
    /// "service errored" versus "service has no data".
    /// </summary>
    public bool Failed(string name) => GetOutcome(name) == BackendCallOutcome.Failed;
}
