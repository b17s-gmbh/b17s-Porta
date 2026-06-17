using b17s.Porta.Auth.Providers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace b17s.Porta.Transformers;

/// <summary>
/// Context provided to transformers containing request information, authentication details,
/// and utilities for calling backend services.
/// </summary>
public sealed class TransformerContext
{
    /// <summary>
    /// The current HTTP context.
    /// </summary>
    public required HttpContext HttpContext { get; init; }

    /// <summary>
    /// The authenticated user's context (claims, tokens, etc.).
    /// </summary>
    public required AuthenticationContext AuthContext { get; init; }

    /// <summary>
    /// Cancellation token for the request.
    /// </summary>
    public required CancellationToken CancellationToken { get; init; }

    /// <summary>
    /// Route values extracted from the URL pattern.
    /// </summary>
    public required IReadOnlyDictionary<string, object?> RouteValues { get; init; }

    /// <summary>
    /// Query string parameters. Supports multi-value query parameters.
    /// Use StringValues.ToString() for single value, or iterate for multiple values.
    /// </summary>
    public required IReadOnlyDictionary<string, StringValues> QueryParameters { get; init; }

    /// <summary>
    /// Request headers from the incoming HTTP request.
    /// </summary>
    public required IReadOnlyDictionary<string, StringValues> RequestHeaders { get; init; }

    /// <summary>
    /// Backend caller for making HTTP requests to backend services.
    /// </summary>
    public required IBackendCaller BackendCaller { get; init; }

    /// <summary>
    /// Custom properties for passing data between middleware/transformers.
    /// </summary>
    public IDictionary<string, object> Properties { get; init; } = new Dictionary<string, object>();

    /// <summary>
    /// Logger for the current transformer.
    /// </summary>
    public required ILogger Logger { get; init; }

    /// <summary>
    /// Whether telemetry (tracing and metrics) is enabled for this request.
    /// This is controlled by <see cref="Configuration.PortaCoreOptions.EnableTelemetry"/>.
    /// Base classes use this to automatically instrument backend calls and transformations.
    /// </summary>
    public bool TelemetryEnabled { get; init; }

    /// <summary>
    /// The authenticated user's identifier, taken from the standard OIDC <c>sub</c> claim when present.
    /// Returns null when the request is unauthenticated or the token has no <c>sub</c> claim.
    /// </summary>
    /// <remarks>
    /// For non-standard claims (e.g., a tenant-specific user ID), use <see cref="GetClaim"/>
    /// or define your own extension methods on <see cref="TransformerContext"/>:
    /// <code>
    /// public static string? UserId(this TransformerContext ctx) => ctx.GetClaim("custom_id");
    /// </code>
    /// </remarks>
    public string? UserId => GetClaim("sub");

    /// <summary>
    /// Returns the first value of a claim from <see cref="AuthContext"/>, or <c>null</c> when the
    /// claim is absent. For a claim type that may carry multiple values, use <see cref="GetClaims"/>.
    /// </summary>
    public string? GetClaim(string name) =>
        AuthContext.Claims.TryGetValue(name, out var values) && values.Length > 0 ? values[0] : null;

    /// <summary>
    /// Returns every value of a claim from <see cref="AuthContext"/> (e.g. multiple <c>role</c>
    /// claims), or an empty list when the claim is absent.
    /// </summary>
    public IReadOnlyList<string> GetClaims(string name) =>
        AuthContext.Claims.TryGetValue(name, out var values) ? values : [];

    /// <summary>
    /// Resolves a service from the request's <see cref="HttpContext.RequestServices"/> container,
    /// throwing if it is not registered. Use this to reach framework services a transformer needs at
    /// request time (e.g. <c>HybridCache</c>) without threading them through a constructor.
    /// </summary>
    /// <typeparam name="T">The service type to resolve.</typeparam>
    /// <exception cref="InvalidOperationException">No service of type <typeparamref name="T"/> is registered.</exception>
    public T GetRequiredService<T>() where T : notnull
        => HttpContext.RequestServices.GetRequiredService<T>();

    /// <summary>
    /// Resolves a service from the request's <see cref="HttpContext.RequestServices"/> container,
    /// returning <c>null</c> when it is not registered. Prefer this over <see cref="GetRequiredService{T}"/>
    /// when a missing service should be handled with a tailored diagnostic rather than the default
    /// container exception.
    /// </summary>
    /// <typeparam name="T">The service type to resolve.</typeparam>
    public T? GetService<T>()
        => HttpContext.RequestServices.GetService<T>();
}
