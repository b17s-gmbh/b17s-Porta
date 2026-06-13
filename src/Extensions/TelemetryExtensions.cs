using b17s.Porta.Middleware;

using Microsoft.AspNetCore.Builder;

namespace b17s.Porta.Extensions;

/// <summary>
/// Extension methods for enabling Porta's opt-in request-lifecycle telemetry middleware.
/// </summary>
public static class TelemetryExtensions
{
    /// <summary>
    /// Registers <see cref="PortaTelemetryMiddleware"/>, which instruments every request that flows
    /// through it with request-lifecycle telemetry.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The same <see cref="IApplicationBuilder"/> for chaining.</returns>
    /// <remarks>
    /// <para>
    /// While Porta's transformer/raw-forward endpoints and backend calls are instrumented
    /// automatically, the BFF has no other always-on middleware - so request-level telemetry that
    /// spans the <em>entire</em> pipeline is opt-in via this call. When registered it emits:
    /// <list type="bullet">
    ///   <item>the <c>bff.request</c> span (one per request, carrying <c>http.method</c>,
    ///     <c>http.route</c>, and <c>http.status_code</c> tags);</item>
    ///   <item>the <c>bff.requests.active</c> in-flight gauge;</item>
    ///   <item>the <c>bff.request.duration</c>, <c>bff.request.size</c>, and
    ///     <c>bff.response.size</c> metrics.</item>
    /// </list>
    /// </para>
    /// <para>
    /// Register it as early as possible - typically the first middleware, before
    /// <c>UseRouting()</c> - so the span and metrics bracket the whole request. The low-cardinality
    /// route <em>template</em> is read back from the matched endpoint after the inner pipeline runs;
    /// requests that match no route are recorded under a single <c>unmatched</c> route series.
    /// </para>
    /// <para>
    /// Honors <see cref="b17s.Porta.Configuration.PortaCoreOptions.EnableTelemetry"/>: when telemetry
    /// is disabled the middleware is a no-op pass-through. Requires <c>AddPortaCore</c> to have
    /// registered Porta's metrics.
    /// </para>
    /// <example>
    /// <code>
    /// var app = builder.Build();
    /// app.UsePortaTelemetry();   // first, so it brackets the full pipeline
    /// app.UseRouting();
    /// // ... auth, endpoints, etc.
    /// </code>
    /// </example>
    /// </remarks>
    public static IApplicationBuilder UsePortaTelemetry(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<PortaTelemetryMiddleware>();
    }
}
