using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Options;

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
public abstract class AggregatingTransformer<TResponse> : MultiBackendTransformer<TResponse>, ICacheableLegIntrospection
{
    private AggregatorBuilder? _builder;

    /// <summary>
    /// Startup-validation hook: expose the configured backend legs (running <see cref="Configure"/>
    /// once if needed) so the endpoint builder can cross-check cacheable legs at boot without making
    /// a request. Explicitly implemented so it stays off the public transformer surface.
    /// </summary>
    IReadOnlyList<BackendCallConfig> ICacheableLegIntrospection.GetConfiguredBackends()
        => GetOrCreateBuilder().GetBackendConfigs();

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

        // SAFETY: validate every cacheable leg BEFORE any backend call, and outside the per-leg
        // try/catch below so a misconfiguration surfaces as a hard error rather than being masked as
        // a Threw outcome on that one leg. The guard refuses to cache a token-forwarding leg unless
        // the key is partitioned per user, and rejects non-GET/HEAD verbs. HybridCache is resolved
        // once here so a missing registration also fails fast (and is shared across legs).
        var namedBackends = GetNamedBackends(context);
        HybridCache? hybridCache = null;
        foreach (var config in backendConfigs)
        {
            if (config.Cache is not null)
            {
                GuardCacheableLegIsSafe(config, namedBackends.Get(config.Name), context);
            }
        }

        var hasCacheableLeg = backendConfigs.Any(c => c.Cache is not null);
        if (hasCacheableLeg)
        {
            // Consumer-registered (services.AddHybridCache()); Porta does not pick a cache backend.
            // Surface a clear remediation instead of the opaque container exception, and do it here so
            // it is not swallowed by the per-leg catch.
            hybridCache = context.GetService<HybridCache>()
                ?? throw new InvalidOperationException(
                    $"Transformer '{transformerName}' has a backend leg that declares .WithCache(...), " +
                    "but no HybridCache is registered. Call services.AddHybridCache() during startup " +
                    "(optionally with a distributed L2 cache such as Redis for HA). See docs/caching.md.");
        }

        // Opt-in, low-noise debugging aid: tag each cacheable leg's span with its cache key hash.
        // Off by default because the key is per-(route/body/user) and would otherwise add unbounded
        // cardinality to the bff.backend span. Resolved once here (not per leg).
        var verboseCacheTelemetry = hasCacheableLeg
            && context.TelemetryEnabled
            && (context.GetService<IOptions<PortaCoreOptions>>()?.Value.VerboseCacheTelemetry ?? false);

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
                var result = await ExecuteBackendCallAsync(config, context, namedBackends, activity, hybridCache, verboseCacheTelemetry);
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

    private async Task<BackendObjectResult> ExecuteBackendCallAsync(
        BackendCallConfig config, TransformerContext context, NamedBackendEndpoints namedBackends,
        Activity? activity, HybridCache? hybridCache, bool verboseCacheTelemetry)
    {
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

        // Resolve the request body once (deterministic for a given context) so it can feed both the
        // cache key and the actual call without invoking the factory twice.
        var body = config.BodyFactory?.Invoke(context);

        activity?.SetTag("cache.enabled", config.Cache is not null);

        if (config.Cache is null)
        {
            // Unchanged from the original behaviour: return the raw result (success flag + value)
            // so the caller can tell an unsuccessful backend response (Failed) apart from a
            // successful-but-empty payload (ReturnedNull).
            return await CallOnceAsync(config, backendRequest, body, context, context.CancellationToken);
        }

        // Safety and HybridCache presence are enforced up-front in TransformAsync (outside the
        // per-leg try/catch); by here the leg is known to be cacheable-safe and the cache is present.
        var cache = hybridCache!;

        var key = BackendCacheKey.Build(config, backendRequest, body, context, GetType().Name);
        var opts = new HybridCacheEntryOptions { Expiration = config.Cache.Ttl };

        // Verbose, opt-in only: surface the (hashed) key so cache behaviour can be traced in
        // production without dumping the cardinality-heavy key on every span by default.
        if (verboseCacheTelemetry)
        {
            activity?.SetTag("cache.key.hash", key);
        }

        // factoryRan tracks whether THIS request executed the backend call. The factory runs only on
        // a true cache miss (or the single winner of a stampede). So cache.hit below means "this
        // request did not perform its own backend round-trip" - which covers both a genuine
        // L1/L2 hit and a stampede waiter coalesced onto another request's in-flight call. The latter
        // did wait on a backend round-trip (just not its own), so a cold burst can report a few hits
        // that weren't served from a stored entry; that is the only inaccuracy in this tag.
        var factoryRan = false;
        try
        {
            var value = await config.Cache.Invoke(
                cache, key, opts,
                async ct =>
                {
                    factoryRan = true;
                    var result = await CallOnceAsync(config, backendRequest, body, context, ct);

                    // GetOrCreateAsync caches whatever the factory returns but never caches a thrown
                    // exception. Throw a sentinel on an unsuccessful response so failures/timeouts are
                    // not stored; a legitimately-null 200 payload (ReturnedNull) IS a cacheable result.
                    if (!result.IsSuccess)
                    {
                        throw new BackendNotCacheableSignal(result);
                    }

                    return result.Value;
                },
                context.CancellationToken);

            activity?.SetTag("cache.hit", !factoryRan);
            return BackendObjectResult.Success(value);
        }
        catch (BackendNotCacheableSignal signal)
        {
            // A failure happened inside the factory: nothing was cached. Convert the sentinel back to
            // the original unsuccessful result so the outcome semantics (Failed/Threw) are preserved.
            activity?.SetTag("cache.hit", false);
            return signal.Result;
        }
    }

    private static Task<BackendObjectResult> CallOnceAsync(
        BackendCallConfig config,
        BackendRequest backendRequest,
        object? body,
        TransformerContext context,
        CancellationToken cancellationToken)
        => config.BodyFactory != null
            ? context.BackendCaller.CallWithBodyAsync(backendRequest, body!, config.ResponseType, cancellationToken)
            : context.BackendCaller.CallAsync(backendRequest, config.ResponseType, cancellationToken);

    private void GuardCacheableLegIsSafe(
        BackendCallConfig config,
        NamedBackendEndpoint endpoint,
        TransformerContext context)
    {
        // Verb + per-user-partition checks are request-context-independent, so they are shared with
        // the boot-time cross-check in TransformerEndpointBuilder.Build().
        BackendCacheValidation.ValidateLegConfiguration(config, endpoint, GetType().Name);

        // A per-user key needs a subject. A null UserId on a varyByUser leg means the endpoint is
        // not actually authenticated - a misconfiguration we fail on rather than collapsing every
        // anonymous caller onto a single shared entry. This one depends on the live request, so it
        // stays here rather than in the shared (boot-time) validator.
        if (config.Cache!.VaryByUser && string.IsNullOrEmpty(context.UserId))
        {
            throw new InvalidOperationException(
                $"Backend leg '{config.Name}' on transformer '{GetType().Name}' is cached with " +
                "varyByUser: true, but the request has no authenticated subject (ctx.UserId is null). " +
                "A per-user cache requires an authenticated endpoint.");
        }
    }

    /// <summary>
    /// Sentinel used to keep an unsuccessful backend result out of the cache. <c>HybridCache</c>
    /// caches whatever the factory returns but never caches a thrown exception, so the factory
    /// throws this on failure and <see cref="ExecuteBackendCallAsync"/> unwraps it back into the
    /// original <see cref="BackendObjectResult"/>.
    /// </summary>
    private sealed class BackendNotCacheableSignal(BackendObjectResult result) : Exception
    {
        public BackendObjectResult Result { get; } = result;
    }
}

/// <summary>
/// Startup-validation hook implemented by every <see cref="AggregatingTransformer{TResponse}"/>.
/// Lets <c>TransformerEndpointBuilder.Build()</c> read a transformer's configured legs at boot -
/// without knowing the closed <c>TResponse</c> - so cacheable-leg misconfiguration surfaces at
/// startup rather than on the first request.
/// </summary>
internal interface ICacheableLegIntrospection
{
    IReadOnlyList<BackendCallConfig> GetConfiguredBackends();
}

/// <summary>
/// Request-context-independent validation for a cacheable backend leg: the GET/HEAD(/POST for
/// GraphQL) verb guard and the "user-varying leg must be partitioned per user" guard. Shared by the
/// request-time guard (<see cref="AggregatingTransformer{TResponse}"/>) and the boot-time cross-check
/// in <c>TransformerEndpointBuilder.Build()</c> so both enforce identical rules.
/// </summary>
internal static class BackendCacheValidation
{
    public static void ValidateLegConfiguration(
        BackendCallConfig config,
        NamedBackendEndpoint endpoint,
        string transformerName)
    {
        var spec = config.Cache!;

        // Only safe-by-construction read verbs may be cached. Caching a mutating verb is almost
        // always a mistake, so reject it loudly rather than silently caching writes. The verb is the
        // endpoint's method; route interpolation never changes it. POST is allowed only for legs that
        // opted in via WithGraphQLCache(...) (GraphQL queries ride POST).
        if (!IsCacheableMethod(endpoint.Method, spec.AllowPost))
        {
            var allowed = spec.AllowPost ? "GET, HEAD, and POST" : "GET and HEAD";
            var api = spec.AllowPost ? "WithGraphQLCache(...)" : ".WithCache(...)";
            throw new InvalidOperationException(
                $"Backend leg '{config.Name}' on transformer '{transformerName}' uses HTTP " +
                $"{endpoint.Method}, which cannot be cached. {api} is only supported " +
                $"for {allowed} legs.");
        }

        // A leg that carries the user's identity to the backend returns per-user data. Sharing one
        // cached entry across users would leak data, so such a leg MUST partition its key per user.
        // Only varyByUser counts here: a custom varyBy is an *additional* dimension (tenant, locale)
        // whose contents we can't inspect, so it cannot stand in for the per-user guarantee - a
        // varyBy that doesn't include the subject would silently re-open the cross-user leak.
        var userVarying = endpoint.ForwardUserToken
            || endpoint.UseTokenExchange
            || BackendAuthPolicies.RequiresUserIdentity(endpoint.BackendAuthPolicy);

        if (userVarying && !spec.VaryByUser)
        {
            var api = spec.AllowPost ? "WithGraphQLCache(...)" : ".WithCache(...)";
            throw new InvalidOperationException(
                $"Backend leg '{config.Name}' on transformer '{transformerName}' forwards the user's " +
                "identity (BearerToken / TokenExchange / user-token forwarding) but is cached without a " +
                "per-user key. Caching it would serve one user's data to another. Add " +
                $"varyByUser: true to {api} (a varyBy key alone is not sufficient - it is an extra " +
                "dimension, not a guarantee the key includes the user), or remove caching from this leg.");
        }
    }

    public static bool IsCacheableMethod(string method, bool allowPost)
        => string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase)
            || string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase)
            || (allowPost && string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Builds the cache key for a single cacheable backend leg. Human-readable namespace prefix
/// (<c>porta:agg:</c>) so operators can find entries (e.g. a Redis <c>SCAN porta:agg:*</c>), with the
/// variable part hashed (SHA-256, hex) to bound length and avoid unsafe key characters.
/// </summary>
internal static class BackendCacheKey
{
    public static string Build(
        BackendCallConfig config,
        BackendRequest request,
        object? body,
        TransformerContext context,
        string transformerName)
    {
        // Contributors, in order: transformer name (isolates two transformers sharing a leg name),
        // leg name, HTTP method, resolved (route-interpolated) URL, optional body hash, optional
        // per-user partition, optional custom contributor.
        var contributors = new StringBuilder()
            .Append(transformerName).Append('|')
            .Append(config.Name).Append('|')
            .Append(request.Method).Append('|')
            .Append(request.Url);

        if (config.BodyFactory != null && body != null)
        {
            contributors.Append("|b:").Append(HashBody(body));
        }

        if (config.Cache!.VaryByUser)
        {
            // GuardCacheableLegIsSafe has already rejected a null subject on a varyByUser leg.
            contributors.Append("|u:").Append(context.UserId);
        }

        if (config.Cache.VaryBy is { } varyBy)
        {
            contributors.Append("|c:").Append(varyBy(context));
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(contributors.ToString()));
        return string.Concat("porta:agg:", Convert.ToHexString(hash));
    }

    private static string HashBody(object body)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(body);
        return Convert.ToHexString(SHA256.HashData(json));
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

    /// <summary>
    /// Cache this backend leg's deserialized result using the application's <c>HybridCache</c>
    /// (register it with <c>services.AddHybridCache()</c>; add a distributed L2 cache such as Redis
    /// for cross-replica HA and stampede protection). Only successful responses are cached - failures,
    /// timeouts, and cancellations are never stored. The cache is keyed by the transformer, the leg
    /// name, the HTTP method, the resolved (route-interpolated) backend URL, and the request body when
    /// present. Only GET and HEAD legs may be cached.
    /// </summary>
    /// <param name="ttl">Absolute time-to-live for the cached entry, and the staleness bound: a cached
    /// value can outlive a logout or permission change for up to this duration. Keep user-varying TTLs short.</param>
    /// <param name="varyByUser">
    /// When <see langword="true"/>, the cache key is partitioned by the authenticated subject
    /// (<see cref="TransformerContext.UserId"/>) so users never share an entry. REQUIRED for any leg
    /// that forwards the user's identity (BearerToken / TokenExchange / user-token forwarding); caching
    /// such a leg without it throws at request time to prevent a cross-user data leak.
    /// </param>
    /// <param name="varyBy">
    /// Optional custom key contributor appended to the key. Use for legs that vary by something other
    /// than the user (tenant id, locale, a route value). Combine with <paramref name="varyByUser"/> as needed.
    /// </param>
    /// <param name="tags">
    /// Optional tags attached to the cached entry. Evict a whole tagged group at once - e.g. from a
    /// webhook the backend calls when the underlying data changes - by injecting <c>HybridCache</c> and
    /// calling <c>RemoveByTagAsync(tag)</c>. Eviction is only cluster-wide when an L2 (distributed) store
    /// is registered; with L1 only it clears the local replica.
    /// </param>
    /// <returns>The builder, for chaining.</returns>
    public BackendCallBuilder<TResponse> WithCache(
        TimeSpan ttl,
        bool varyByUser = false,
        Func<TransformerContext, string>? varyBy = null,
        IReadOnlyList<string>? tags = null)
    {
        _config.Cache = BuildCacheSpec(ttl, varyByUser, varyBy, tags, allowPost: false);
        return this;
    }

    /// <summary>
    /// Cache this backend leg's deserialized result like <see cref="WithCache"/>, but for a
    /// GraphQL-over-<c>POST</c> leg. GraphQL queries ride <c>POST</c>, so the GET/HEAD-only verb guard
    /// would otherwise reject them; this method opts the leg into <c>POST</c> caching explicitly. The
    /// cache key incorporates the request body (the GraphQL query + variables), so different queries are
    /// different entries automatically.
    /// </summary>
    /// <remarks>
    /// CALLER RESPONSIBILITY: only cache GraphQL <b>query</b> operations. A GraphQL <c>mutation</c> also
    /// rides <c>POST</c> and Porta cannot tell the two apart by verb - caching one would cache a write.
    /// All the other <see cref="WithCache"/> rules still apply (fail-closed per-user safety, only
    /// successful responses cached, TTL as staleness bound).
    /// </remarks>
    /// <param name="ttl">Absolute time-to-live for the cached entry, and the staleness bound.</param>
    /// <param name="varyByUser">Partition the key by the authenticated subject. REQUIRED for any leg that
    /// forwards the user's identity; caching such a leg without it throws.</param>
    /// <param name="varyBy">Optional custom key contributor (tenant, locale, ...).</param>
    /// <param name="tags">Optional tags for group eviction via <c>HybridCache.RemoveByTagAsync</c>.</param>
    /// <returns>The builder, for chaining.</returns>
    public BackendCallBuilder<TResponse> WithGraphQLCache(
        TimeSpan ttl,
        bool varyByUser = false,
        Func<TransformerContext, string>? varyBy = null,
        IReadOnlyList<string>? tags = null)
    {
        _config.Cache = BuildCacheSpec(ttl, varyByUser, varyBy, tags, allowPost: true);
        return this;
    }

    private static CacheSpec BuildCacheSpec(
        TimeSpan ttl,
        bool varyByUser,
        Func<TransformerContext, string>? varyBy,
        IReadOnlyList<string>? tags,
        bool allowPost)
        => new(
            Ttl: ttl,
            VaryByUser: varyByUser,
            VaryBy: varyBy,
            Tags: tags,
            AllowPost: allowPost,
            // Capture TResponse here so the (otherwise non-generic) config can drive a strongly-typed
            // HybridCache.GetOrCreateAsync<TResponse> - correct System.Text.Json (de)serialization for
            // the L2 cache - without reflection on a runtime Type. The boxed object? factory supplied by
            // the call site is adapted to TResponse inside. Captures the leg's tags so a tagged entry can
            // later be evicted as a group via HybridCache.RemoveByTagAsync.
            Invoke: async (cache, key, opts, factory, ct) =>
            {
                var value = await cache.GetOrCreateAsync(
                    key,
                    factory,
                    // The boxed object? is the leg's deserialized payload. A successful-but-null 200
                    // (ReturnedNull) reaches here as null; pattern-match rather than a hard (TResponse)
                    // cast so a null payload on a value-type TResponse yields default(T) instead of an
                    // NRE on the unbox. Reference-type legs keep the same null behaviour as before.
                    static async (f, c) => await f(c) is TResponse v ? v : default!,
                    opts,
                    tags: tags,
                    cancellationToken: ct);
                return value;
            });
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

    /// <summary>
    /// Per-leg caching configuration, or <see langword="null"/> when the leg is not cached
    /// (the unchanged, always-live code path).
    /// </summary>
    public CacheSpec? Cache { get; set; }
}

/// <summary>
/// Caching configuration for a single backend leg, captured by
/// <see cref="BackendCallBuilder{TResponse}.WithCache(TimeSpan, bool, Func{TransformerContext, string}, IReadOnlyList{string})"/>.
/// </summary>
/// <param name="Ttl">Absolute time-to-live for the cached entry.</param>
/// <param name="VaryByUser">Whether the cache key is partitioned by the authenticated subject.</param>
/// <param name="VaryBy">Optional custom key contributor.</param>
/// <param name="Invoke">
/// Strongly-typed bridge to <c>HybridCache.GetOrCreateAsync&lt;TResponse&gt;</c>. Closes over the leg's
/// response type at the builder call site so the runtime <see cref="BackendCallConfig.ResponseType"/>
/// never has to be reflected over; the boxed <c>object?</c> factory is adapted to the typed factory inside.
/// </param>
/// <param name="Tags">Optional tags attached to the cached entry for group eviction via
/// <c>HybridCache.RemoveByTagAsync</c>; <see langword="null"/> when the leg is untagged.</param>
/// <param name="AllowPost">Whether the leg may be cached over <c>POST</c> (set by
/// <see cref="BackendCallBuilder{TResponse}.WithGraphQLCache"/> for GraphQL queries). When
/// <see langword="false"/> only GET/HEAD legs are cacheable.</param>
internal sealed record CacheSpec(
    TimeSpan Ttl,
    bool VaryByUser,
    Func<TransformerContext, string>? VaryBy,
    Func<HybridCache, string, HybridCacheEntryOptions,
         Func<CancellationToken, ValueTask<object?>>, CancellationToken, ValueTask<object?>> Invoke,
    IReadOnlyList<string>? Tags = null,
    bool AllowPost = false);

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
