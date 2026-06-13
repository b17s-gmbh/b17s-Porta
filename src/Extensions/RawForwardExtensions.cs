using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace b17s.Porta.Extensions;

/// <summary>
/// Extension methods for configuring raw forwarding endpoints.
/// </summary>
public static class RawForwardExtensions
{
    /// <summary>
    /// Creates a zero-code raw forwarding endpoint that streams requests/responses without transformation.
    /// Use this for binary content, file uploads/downloads, or non-JSON APIs.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder</param>
    /// <returns>A fluent builder for configuring the raw forward endpoint</returns>
    /// <remarks>
    /// <para>
    /// Raw forwarding is ideal for:
    /// <list type="bullet">
    ///   <item><description>Binary content (images, files, PDFs)</description></item>
    ///   <item><description>Non-JSON APIs (XML, text, custom formats)</description></item>
    ///   <item><description>Large payloads where buffering would be expensive</description></item>
    ///   <item><description>Performance-critical endpoints where transformation isn't needed</description></item>
    /// </list>
    /// </para>
    /// <para>
    /// Unlike regular transformers, raw forwarding:
    /// <list type="bullet">
    ///   <item><description>Streams request/response bodies without buffering</description></item>
    ///   <item><description>Preserves Content-Type headers</description></item>
    ///   <item><description>Does not deserialize or serialize JSON</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Zero-code proxy - no transformer class needed
    /// app.MapRawForward()
    ///     .FromGet("/api/files/{id}")
    ///     .ToGet("https://files.internal/files/{id}")
    ///     .WithBackendAuth(BackendAuthPolicies.BasicAuth)
    ///     .AllowAnonymous()
    ///     .Build();
    ///
    /// // Download proxy with auth
    /// app.MapRawForward()
    ///     .FromGet("/api/documents/{id}/download")
    ///     .ToGet("https://docs.internal/documents/{id}/content")
    ///     .RequireAuth()
    ///     .Build();
    ///
    /// // Upload proxy
    /// app.MapRawForward()
    ///     .FromPost("/api/uploads")
    ///     .ToPost("https://uploads.internal/files")
    ///     .WithBackendAuth(BackendAuthPolicies.BearerToken)
    ///     .Build();
    /// </code>
    /// </example>
    public static RawForwardEndpointBuilder<DefaultRawForwardTransformer> MapRawForward(this IEndpointRouteBuilder endpoints)
        => new(endpoints, endpoints.ServiceProvider);

    /// <summary>
    /// Creates a raw forwarding endpoint with a custom transformer for request/response header manipulation.
    /// </summary>
    /// <typeparam name="TTransformer">A type implementing <see cref="IRawTransformer"/></typeparam>
    /// <param name="endpoints">The endpoint route builder</param>
    /// <returns>A fluent builder for configuring the raw forward endpoint</returns>
    /// <remarks>
    /// <para>
    /// Use a custom transformer when you need to:
    /// <list type="bullet">
    ///   <item><description>Add headers based on user claims (e.g., tenant ID)</description></item>
    ///   <item><description>Remove internal headers from responses</description></item>
    ///   <item><description>Add security or caching headers</description></item>
    ///   <item><description>Validate requests before forwarding</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Custom transformer with header manipulation
    /// [RequiresAuthentication]
    /// public class SecureFileTransformer : RawForwardTransformer
    /// {
    ///     protected override void ModifyRequest(HttpRequestMessage request, TransformerContext context)
    ///     {
    ///         var tenantId = context.GetClaim("tenant_id");
    ///         if (!string.IsNullOrEmpty(tenantId))
    ///             request.Headers.Add("X-Tenant-Id", tenantId);
    ///     }
    ///
    ///     protected override void ModifyResponseHeaders(HttpResponseHeaders headers, TransformerContext context)
    ///     {
    ///         headers.Remove("X-Internal-Debug");
    ///         headers.Remove("X-Backend-Server");
    ///     }
    /// }
    ///
    /// // Registration
    /// builder.Services.AddScoped&lt;SecureFileTransformer&gt;();
    ///
    /// // Endpoint
    /// app.MapRawForward&lt;SecureFileTransformer&gt;()
    ///     .FromGet("/api/secure-files/{id}")
    ///     .ToGet("https://files.internal/files/{id}")
    ///     .Build();
    /// </code>
    /// </example>
    public static RawForwardEndpointBuilder<TTransformer> MapRawForward<TTransformer>(this IEndpointRouteBuilder endpoints)
        where TTransformer : class, IRawTransformer
        => new(endpoints, endpoints.ServiceProvider);

    /// <summary>
    /// Registers a raw forward transformer in the DI container.
    /// </summary>
    /// <typeparam name="TTransformer">The raw transformer type implementing <see cref="IRawTransformer"/> to register as a scoped service.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddRawForwardTransformer<TTransformer>(this IServiceCollection services)
        where TTransformer : class, IRawTransformer
        => services.AddScoped<TTransformer>();
}
