using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace b17s.Porta.Extensions;

/// <summary>
/// Extension methods for registering and mapping transformer endpoints.
/// Core service registration (HttpClient, registry, metrics, etc.) lives in
/// <see cref="PortaServiceExtensions.AddPortaCore(IServiceCollection, Action{b17s.Porta.Configuration.PortaCoreOptions})"/>.
/// </summary>
public static class TransformerExtensions
{
    /// <summary>
    /// Maps a transformer to an endpoint with fluent configuration.
    /// </summary>
    /// <typeparam name="TTransformer">The transformer type</typeparam>
    /// <typeparam name="TRequest">The request body type</typeparam>
    /// <typeparam name="TResponse">The response body type</typeparam>
    /// <param name="endpoints">The endpoint route builder</param>
    /// <returns>A fluent builder for configuring the transformer endpoint</returns>
    public static TransformerEndpointBuilder<TTransformer, TRequest, TResponse> MapTransformer<TTransformer, TRequest, TResponse>(
        this IEndpointRouteBuilder endpoints)
        where TTransformer : class, ITransformer<TRequest, TResponse>
        // Note: Transformer registration is validated at request time, not at startup
        // Transformers must be registered beforehand via AddTransformer<T>()
        => new(endpoints, endpoints.ServiceProvider);

    /// <summary>
    /// Maps a transformer with no request body (for GET, DELETE, etc.).
    /// </summary>
    /// <typeparam name="TTransformer">The transformer type</typeparam>
    /// <typeparam name="TResponse">The response body type</typeparam>
    /// <param name="endpoints">The endpoint route builder</param>
    /// <returns>A fluent builder for configuring the transformer endpoint</returns>
    public static TransformerEndpointBuilder<TTransformer, TResponse> MapTransformer<TTransformer, TResponse>(
        this IEndpointRouteBuilder endpoints)
        where TTransformer : class, ITransformer<TResponse>
        => new(endpoints, endpoints.ServiceProvider);

    /// <summary>
    /// Registers a transformer in the DI container.
    /// Call this in your service configuration before calling MapTransformer.
    /// </summary>
    /// <typeparam name="TTransformer">The transformer type to register as a scoped service.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddTransformer<TTransformer>(this IServiceCollection services)
        where TTransformer : class
    {
        services.AddScoped<TTransformer>();
        return services;
    }

    /// <summary>
    /// Registers multiple transformer types at once. Equivalent to calling
    /// <see cref="AddTransformer{TTransformer}"/> for each type.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="transformerTypes">The transformer types to register as scoped services.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddTransformerTypes(this IServiceCollection services, params Type[] transformerTypes)
    {
        foreach (var type in transformerTypes)
        {
            services.AddScoped(type);
        }
        return services;
    }
}

/// <summary>
/// Configures which sensitive headers are allowed to be forwarded to backends in raw-forward
/// mode, and to which backend hosts. Headers not on the allow-list (Cookie, Authorization,
/// the standard Forwarded header, and the X-Forwarded-* family) are stripped before the request
/// is sent. The forwarding-metadata headers (Forwarded, X-Forwarded-*) are additionally relayed
/// when the inbound connection comes from a proxy listed in <see cref="TrustedForwardingProxies"/>.
/// Symmetrically, sensitive backend response headers (Set-Cookie, Strict-Transport-Security,
/// Content-Security-Policy, Server, X-Powered-By) are stripped on the way back to the client
/// unless added to <see cref="AllowedResponseHeaders"/>.
/// </summary>
public sealed class RawForwardHeaderPassThrough
{
    /// <summary>
    /// Header names to forward despite the default-strip list. Case-insensitive.
    /// Example: ["Authorization"] to allow client-supplied Authorization headers through.
    /// </summary>
    public HashSet<string> AllowedHeaders { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Backend host names that allowed headers may be forwarded to. Case-insensitive,
    /// matched against the destination URL host. If empty, AllowedHeaders apply to all
    /// destinations. If non-empty, AllowedHeaders only pass through when the destination
    /// host is in this set.
    /// </summary>
    public HashSet<string> AllowedDestinationHosts { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Backend response header names that should be forwarded to the client despite the
    /// default-strip list (Set-Cookie, Strict-Transport-Security, Content-Security-Policy,
    /// Server, X-Powered-By). Case-insensitive. Allowing Set-Cookie lets a backend plant
    /// cookies on the BFF's domain, which can shadow the BFF session cookie; opt in only
    /// when you understand and accept that risk.
    /// </summary>
    public HashSet<string> AllowedResponseHeaders { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// IP addresses or CIDR ranges of trusted reverse proxies that sit in front of the BFF.
    /// When the inbound connection's remote IP matches one of these, the client-supplied
    /// forwarding-metadata headers (the standard <c>Forwarded</c> header and the
    /// <c>X-Forwarded-*</c> family) are relayed to the backend instead of being stripped, so
    /// a legitimate front proxy's forwarding chain reaches the backend intact.
    /// <para>
    /// Entries may be single addresses (<c>"10.0.0.5"</c>, <c>"::1"</c>) or CIDR ranges
    /// (<c>"10.0.0.0/8"</c>, <c>"fd00::/8"</c>). IPv4-mapped IPv6 remote addresses are
    /// normalized before comparison, so an IPv4 entry matches a dual-stack
    /// <c>::ffff:10.0.0.5</c> peer.
    /// </para>
    /// <para>
    /// SECURITY: leave this empty unless the BFF is genuinely behind a reverse proxy. Any host
    /// listed here is fully trusted to dictate the forwarded client IP, host, and scheme that
    /// downstream backends (and their forwarded-header middleware) may act on. Listing a broad
    /// range or an untrusted network lets clients spoof that metadata.
    /// </para>
    /// </summary>
    public HashSet<string> TrustedForwardingProxies { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Fluent builder for creating zero-code pass-through endpoints.
/// Use when you just need to forward requests to a backend without transformation.
/// Internally delegates to <see cref="TransformerEndpointBuilder{TTransformer, TResponse}"/>
/// with a synthetic <see cref="BackendForwardingTransformer{TResponse}"/>, so pass-through
/// endpoints inherit telemetry, <c>When</c>-predicate routing, and the post-Build()
/// anonymous-smuggling recheck.
/// </summary>
/// <typeparam name="TResponse">The response type from the backend</typeparam>
public sealed class PassThroughEndpointBuilder<TResponse>
{
    private readonly TransformerEndpointBuilder<BackendForwardingTransformer<TResponse>, TResponse> _inner;

    internal PassThroughEndpointBuilder(IEndpointRouteBuilder endpoints, IServiceProvider services)
        => _inner = new TransformerEndpointBuilder<BackendForwardingTransformer<TResponse>, TResponse>(endpoints, services);

    /// <summary>Specifies the incoming HTTP method and route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromRoute(string method, string routePattern)
    {
        _inner.FromRoute(method, routePattern);
        return this;
    }

    /// <summary>Specifies a GET route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromGet(string routePattern) => FromRoute("GET", routePattern);

    /// <summary>Specifies a POST route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromPost(string routePattern) => FromRoute("POST", routePattern);

    /// <summary>Specifies a PUT route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromPut(string routePattern) => FromRoute("PUT", routePattern);

    /// <summary>Specifies a DELETE route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromDelete(string routePattern) => FromRoute("DELETE", routePattern);

    /// <summary>Specifies a PATCH route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromPatch(string routePattern) => FromRoute("PATCH", routePattern);

    /// <summary>Specifies a HEAD route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromHead(string routePattern) => FromRoute("HEAD", routePattern);

    /// <summary>Specifies an OPTIONS route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromOptions(string routePattern) => FromRoute("OPTIONS", routePattern);

    /// <summary>Matches any HTTP method on the specified route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromAny(string routePattern)
    {
        _inner.FromAny(routePattern);
        return this;
    }

    /// <summary>
    /// Adds a runtime predicate that must return true for this endpoint to handle the request.
    /// See <see cref="TransformerEndpointBuilderBase{TTransformer, TBuilder}.When"/>.
    /// </summary>
    public PassThroughEndpointBuilder<TResponse> When(Func<HttpContext, bool> predicate)
    {
        _inner.When(predicate);
        return this;
    }

    /// <summary>Specifies the backend HTTP method and URL.</summary>
    public PassThroughEndpointBuilder<TResponse> ToBackend(string method, string url, ContentType contentType = ContentType.Json)
    {
        _inner.ToBackend(method, url, contentType);
        return this;
    }

    /// <summary>Specifies a GET backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public PassThroughEndpointBuilder<TResponse> ToGet(string url, ContentType contentType = ContentType.Json) => ToBackend("GET", url, contentType);

    /// <summary>Specifies a POST backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public PassThroughEndpointBuilder<TResponse> ToPost(string url, ContentType contentType = ContentType.Json) => ToBackend("POST", url, contentType);

    /// <summary>Specifies a PUT backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public PassThroughEndpointBuilder<TResponse> ToPut(string url, ContentType contentType = ContentType.Json) => ToBackend("PUT", url, contentType);

    /// <summary>Specifies a DELETE backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public PassThroughEndpointBuilder<TResponse> ToDelete(string url, ContentType contentType = ContentType.Json) => ToBackend("DELETE", url, contentType);

    /// <summary>Specifies a PATCH backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public PassThroughEndpointBuilder<TResponse> ToPatch(string url, ContentType contentType = ContentType.Json) => ToBackend("PATCH", url, contentType);

    /// <summary>Forwards to backend using the same HTTP method as the incoming request.</summary>
    public PassThroughEndpointBuilder<TResponse> ToAny(string url)
    {
        _inner.ToAny(url);
        return this;
    }

    /// <summary>Configures the backend as a GraphQL endpoint (POST).</summary>
    public PassThroughEndpointBuilder<TResponse> ToGraphQL(string url)
    {
        _inner.ToGraphQL(url);
        return this;
    }

    /// <summary>Requires authentication with an optional policy.</summary>
    public PassThroughEndpointBuilder<TResponse> RequireAuth(string? policy = null)
    {
        _inner.RequireAuth(policy);
        return this;
    }

    /// <summary>Allows anonymous access.</summary>
    public PassThroughEndpointBuilder<TResponse> AllowAnonymous()
    {
        _inner.AllowAnonymous();
        return this;
    }

    /// <summary>
    /// Allows anonymous access but still populates the auth context if credentials are present.
    /// </summary>
    public PassThroughEndpointBuilder<TResponse> AllowAnonymousWithOptionalAuth()
    {
        _inner.AllowAnonymousWithOptionalAuth();
        return this;
    }

    /// <summary>Sets a timeout for the backend call.</summary>
    public PassThroughEndpointBuilder<TResponse> WithTimeout(TimeSpan timeout)
    {
        _inner.WithTimeout(timeout);
        return this;
    }

    /// <summary>Specifies the backend authentication policy.</summary>
    public PassThroughEndpointBuilder<TResponse> WithBackendAuth(string policy)
    {
        _inner.WithBackendAuth(policy);
        return this;
    }

    /// <summary>
    /// Uses RFC 8693 token exchange to obtain a backend-specific token for the given audience.
    /// </summary>
    /// <param name="audience">The target audience for the exchanged token.</param>
    public PassThroughEndpointBuilder<TResponse> WithTokenExchange(string audience)
    {
        _inner.WithTokenExchange(audience);
        return this;
    }

    /// <summary>Enables automatic retries for transient failures.</summary>
    public PassThroughEndpointBuilder<TResponse> WithRetries(int maxAttempts = 3)
    {
        _inner.WithRetries(maxAttempts);
        return this;
    }

    /// <summary>Builds and registers the pass-through endpoint.</summary>
    public RouteHandlerBuilder Build() => _inner.Build();
}

/// <summary>
/// Extension methods for zero-code pass-through endpoints.
/// </summary>
public static class PassThroughExtensions
{
    /// <summary>
    /// Creates a zero-code pass-through endpoint that forwards requests to a backend and returns the response as-is.
    /// No transformer class needed - just configure and build.
    /// </summary>
    /// <typeparam name="TResponse">The response type from the backend</typeparam>
    /// <param name="endpoints">The endpoint route builder</param>
    /// <returns>A fluent builder for configuring the pass-through endpoint</returns>
    /// <example>
    /// // Zero-code endpoint - no transformer class needed!
    /// app.MapPassThrough&lt;ProductsResponse&gt;()
    ///     .FromRoute("GET", "/api/products")
    ///     .ToBackend("GET", $"{backendUrl}/products")
    ///     .WithBackendAuth(BackendAuthPolicies.BasicAuth)
    ///     .Build();
    /// </example>
    public static PassThroughEndpointBuilder<TResponse> MapPassThrough<TResponse>(this IEndpointRouteBuilder endpoints)
        => new(endpoints, endpoints.ServiceProvider);

    /// <summary>
    /// Creates a zero-code pass-through endpoint with a combined fluent API.
    /// Shorter syntax for simple cases.
    /// </summary>
    /// <typeparam name="TResponse">The response type from the backend</typeparam>
    /// <param name="endpoints">The endpoint route builder</param>
    /// <param name="method">The HTTP method</param>
    /// <param name="routePattern">The route pattern</param>
    /// <returns>A fluent builder for configuring the pass-through endpoint</returns>
    /// <example>
    /// app.MapPassThrough&lt;ProductsResponse&gt;("GET", "/api/products")
    ///     .ToBackend("GET", $"{backendUrl}/products")
    ///     .WithBackendAuth(BackendAuthPolicies.BasicAuth)
    ///     .Build();
    /// </example>
    public static PassThroughEndpointBuilder<TResponse> MapPassThrough<TResponse>(
        this IEndpointRouteBuilder endpoints,
        string method,
        string routePattern)
    {
        return new PassThroughEndpointBuilder<TResponse>(endpoints, endpoints.ServiceProvider)
            .FromRoute(method, routePattern);
    }
}
