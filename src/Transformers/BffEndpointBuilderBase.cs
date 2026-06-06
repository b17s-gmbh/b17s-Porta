using System;

namespace b17s.Porta.Transformers;

/// <summary>
/// Common base class for fluent BFF endpoint builders.
/// Extracts duplicate configuration methods for HTTP mapping, timeouts, and auth policies.
/// </summary>
public abstract class BffEndpointBuilderBase<TBuilder>
    where TBuilder : BffEndpointBuilderBase<TBuilder>
{
    private protected string? _httpMethod;
    private protected string? _routePattern;
    private protected string? _backendMethod;
    private protected string? _backendUrl;
    private protected string? _authPolicy;
    private protected bool? _requireAuth;
    private protected TimeSpan? _timeout;
    private protected string? _backendAuthPolicy;

    protected TBuilder Self => (TBuilder)this;

    /// <summary>
    /// Specifies the incoming HTTP method and route pattern.
    /// </summary>
    public TBuilder FromRoute(string method, string routePattern)
    {
        _httpMethod = method.ToUpperInvariant();
        _routePattern = routePattern;
        return Self;
    }

    /// <summary>Specifies a GET route pattern.</summary>
    public TBuilder FromGet(string routePattern) => FromRoute("GET", routePattern);

    /// <summary>Specifies a POST route pattern.</summary>
    public TBuilder FromPost(string routePattern) => FromRoute("POST", routePattern);

    /// <summary>Specifies a PUT route pattern.</summary>
    public TBuilder FromPut(string routePattern) => FromRoute("PUT", routePattern);

    /// <summary>Specifies a DELETE route pattern.</summary>
    public TBuilder FromDelete(string routePattern) => FromRoute("DELETE", routePattern);

    /// <summary>Specifies a PATCH route pattern.</summary>
    public TBuilder FromPatch(string routePattern) => FromRoute("PATCH", routePattern);

    /// <summary>Specifies a HEAD route pattern.</summary>
    public TBuilder FromHead(string routePattern) => FromRoute("HEAD", routePattern);

    /// <summary>Specifies an OPTIONS route pattern.</summary>
    public TBuilder FromOptions(string routePattern) => FromRoute("OPTIONS", routePattern);

    /// <summary>
    /// Matches any HTTP method on the specified route pattern.
    /// </summary>
    public TBuilder FromAny(string routePattern)
    {
        _httpMethod = "*";
        _routePattern = routePattern;
        return Self;
    }

    /// <summary>
    /// Forwards to backend using the same HTTP method as the incoming request.
    /// </summary>
    public TBuilder ToAny(string url)
    {
        _backendMethod = "*";
        _backendUrl = url;
        return Self;
    }

    /// <summary>Requires authentication with an optional policy.</summary>
    public TBuilder RequireAuth(string? policy = null)
    {
        _requireAuth = true;
        _authPolicy = policy;
        return Self;
    }

    /// <summary>Allows anonymous access (no authentication required).</summary>
    public TBuilder AllowAnonymous()
    {
        _requireAuth = false;
        _authPolicy = null;
        return Self;
    }

    /// <summary>Sets a timeout for the backend call.</summary>
    public TBuilder WithTimeout(TimeSpan timeout)
    {
        _timeout = timeout;
        return Self;
    }

    /// <summary>Specifies the backend authentication policy.</summary>
    public TBuilder WithBackendAuth(string policy)
    {
        _backendAuthPolicy = policy;
        return Self;
    }
}
