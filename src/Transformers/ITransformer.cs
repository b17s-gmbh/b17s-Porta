using System.Net.Http.Headers;

namespace b17s.Porta.Transformers;

/// <summary>
/// Marker interface for raw forwarding transformers that bypass JSON parsing.
/// Implement this interface for zero-transformation proxying of binary content,
/// file uploads/downloads, or when you need maximum performance without serialization overhead.
/// </summary>
/// <remarks>
/// Raw transformers stream the response body directly without parsing, supporting:
/// <list type="bullet">
///   <item><description>Binary content (images, files, PDFs)</description></item>
///   <item><description>Non-JSON APIs (XML, text, custom formats)</description></item>
///   <item><description>Large payloads where buffering would be expensive</description></item>
///   <item><description>Performance-critical endpoints where transformation isn't needed</description></item>
/// </list>
/// <para/>
/// Use <see cref="RawForwardTransformer"/> as a base class for implementing raw transformers
/// with optional request/response header manipulation.
/// <para/>
/// Example usage:
/// <code>
/// // Zero-code proxy (no transformer class needed)
/// app.MapRawForward()
///     .FromRoute("GET", "/api/files/{id}")
///     .ToBackend("GET", $"{fileServiceUrl}/files/{{id}}")
///     .Build();
///
/// // With hooks for header manipulation
/// public class SecureFileTransformer : RawForwardTransformer
/// {
///     protected override void ModifyRequest(HttpRequestMessage request, TransformerContext context)
///     {
///         request.Headers.Add("X-Tenant-Id", context.GetClaim("tenant_id"));
///     }
/// }
/// </code>
/// </remarks>
public interface IRawTransformer
{
    /// <summary>
    /// Called before the request is sent to the backend.
    /// Override to add custom headers, modify the URL, or perform validation.
    /// </summary>
    /// <param name="request">The HTTP request message to be sent to the backend</param>
    /// <param name="context">The transformer context with auth info, route values, etc.</param>
    void ModifyRequest(HttpRequestMessage request, TransformerContext context) { }

    /// <summary>
    /// Called after receiving the response from the backend, before returning to the client.
    /// Override to strip internal headers or add custom response headers.
    /// Note: The response body is streamed and cannot be modified.
    /// </summary>
    /// <param name="headers">The response headers that will be returned to the client</param>
    /// <param name="context">The transformer context with auth info, route values, etc.</param>
    void ModifyResponseHeaders(HttpResponseHeaders headers, TransformerContext context) { }
}

/// <summary>
/// Non-generic marker implemented by every transformer interface
/// (<see cref="ITransformer{TRequest, TResponse}"/> and <see cref="ITransformer{TResponse}"/>).
/// Exists so registration helpers like
/// <c>AddTransformer&lt;T&gt;()</c> / <c>AddTransformerTypes(params Type[])</c> can verify at
/// compile time / registration time that a type is actually a transformer.
/// </summary>
public interface ITransformer;

/// <summary>
/// Base interface for all request/response transformers.
/// Transformers act as middleware between incoming requests and backend API calls,
/// with built-in authentication, validation, and transformation capabilities.
/// </summary>
/// <typeparam name="TRequest">The request body type (or empty for no body)</typeparam>
/// <typeparam name="TResponse">The response body type</typeparam>
public interface ITransformer<TRequest, TResponse> : ITransformer
{
    /// <summary>
    /// Transforms an incoming request and forwards it to the backend service.
    /// </summary>
    /// <param name="request">The deserialized request body (null for GET/DELETE)</param>
    /// <param name="context">Context containing auth info, HTTP context, and backend caller</param>
    /// <returns>The transformed response from the backend</returns>
    Task<TResponse> TransformAsync(TRequest? request, TransformerContext context);
}

/// <summary>
/// Base interface for all request/response transformers.
/// Transformers act as middleware between incoming requests and backend API calls,
/// with built-in authentication, validation, and transformation capabilities.
/// </summary>
/// <typeparam name="TResponse">The response body type</typeparam>
public interface ITransformer<TResponse> : ITransformer
{
    /// <summary>
    /// Transforms an incoming request and forwards it to the backend service.
    /// </summary>
    /// <param name="context">Context containing auth info, HTTP context, and backend caller</param>
    /// <returns>The transformed response from the backend</returns>
    Task<TResponse> TransformAsync(TransformerContext context);
}
