using System.Net.Http.Headers;

namespace b17s.Porta.Transformers;

/// <summary>
/// Base class for raw forwarding transformers that bypass JSON parsing.
/// Use this for binary content, non-JSON APIs, or maximum performance scenarios.
/// </summary>
/// <remarks>
/// <para>
/// Raw transformers stream the response body directly without parsing, making them ideal for:
/// <list type="bullet">
///   <item><description>Binary content (images, files, PDFs)</description></item>
///   <item><description>Non-JSON APIs (XML, text, custom formats)</description></item>
///   <item><description>Large payloads where buffering would be expensive</description></item>
///   <item><description>Performance-critical endpoints where transformation isn't needed</description></item>
/// </list>
/// </para>
/// <para>
/// Override <see cref="ModifyRequest"/> to add headers or modify the request before it's sent.
/// Override <see cref="ModifyResponseHeaders"/> to filter or add response headers.
/// </para>
/// </remarks>
/// <example>
/// <code>
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
/// // Register and use
/// app.MapRawForward&lt;SecureFileTransformer&gt;()
///     .FromRoute("GET", "/api/secure-files/{id}")
///     .ToBackend("GET", $"{fileServiceUrl}/files/{{id}}")
///     .Build();
/// </code>
/// </example>
public abstract class RawForwardTransformer : IRawTransformer
{
    /// <summary>
    /// Called before the request is sent to the backend.
    /// Override to add custom headers, modify the URL, or perform validation.
    /// </summary>
    /// <param name="request">The HTTP request message to be sent to the backend</param>
    /// <param name="context">The transformer context with auth info, route values, etc.</param>
    /// <remarks>
    /// Common uses:
    /// <list type="bullet">
    ///   <item><description>Add tenant ID from claims: <c>request.Headers.Add("X-Tenant-Id", context.GetClaim("tenant_id"))</c></description></item>
    ///   <item><description>Add correlation ID: <c>request.Headers.Add("X-Correlation-Id", Activity.Current?.Id)</c></description></item>
    ///   <item><description>Modify query string: Append parameters based on context</description></item>
    /// </list>
    /// </remarks>
    protected virtual void ModifyRequest(HttpRequestMessage request, TransformerContext context)
    {
        // Default: no modifications
    }

    /// <summary>
    /// Called after receiving the response from the backend, before returning to the client.
    /// Override to strip internal headers or add custom response headers.
    /// </summary>
    /// <param name="headers">The response headers that will be returned to the client</param>
    /// <param name="context">The transformer context with auth info, route values, etc.</param>
    /// <remarks>
    /// Common uses:
    /// <list type="bullet">
    ///   <item><description>Remove internal headers: <c>headers.Remove("X-Internal-Debug")</c></description></item>
    ///   <item><description>Add cache headers: <c>headers.CacheControl = new CacheControlHeaderValue { MaxAge = TimeSpan.FromHours(1) }</c></description></item>
    ///   <item><description>Add security headers: <c>headers.Add("X-Content-Type-Options", "nosniff")</c></description></item>
    /// </list>
    /// Note: The response body is streamed and cannot be modified.
    /// </remarks>
    protected virtual void ModifyResponseHeaders(HttpResponseHeaders headers, TransformerContext context)
    {
        // Default: no modifications
    }

    // IRawTransformer explicit implementations
    void IRawTransformer.ModifyRequest(HttpRequestMessage request, TransformerContext context)
        => ModifyRequest(request, context);

    void IRawTransformer.ModifyResponseHeaders(HttpResponseHeaders headers, TransformerContext context)
        => ModifyResponseHeaders(headers, context);
}

/// <summary>
/// Default transformer used for zero-code raw forwarding endpoints.
/// This is used when MapRawForward() is called without a custom transformer type.
/// </summary>
public sealed class DefaultRawForwardTransformer : RawForwardTransformer
{
    // Uses all default behaviors - no modifications
}
