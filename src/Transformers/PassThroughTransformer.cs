using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Transformers;

/// <summary>
/// A transformer that simply passes through the backend response without transformation.
/// Use this as a base class when you don't need to send a request body.
/// </summary>
/// <typeparam name="TResponse">The response type from backend</typeparam>
/// <example>
/// // Zero-code transformer - just inherit:
/// public class ProductsTransformer : PassThroughTransformer&lt;ProductsResponse&gt;;
///
/// // Or with auth requirement:
/// public class MyDataTransformer : PassThroughTransformer&lt;MyData&gt;
/// {
///     protected override bool RequiresAuthentication =&gt; true;
/// }
/// </example>
public abstract class PassThroughTransformer<TResponse> : TransformerBase<TResponse>
{
    /// <summary>
    /// Override to require authentication. Default is false.
    /// When true, returns 401 if UserId is null.
    /// </summary>
    protected virtual bool RequiresAuthentication => false;

    /// <summary>
    /// Optional: Transform the response before returning.
    /// Default implementation returns the response as-is.
    /// </summary>
    protected virtual TResponse TransformResponse(TResponse response, TransformerContext context) => response;

    public override async Task<TResponse> TransformAsync(TransformerContext context)
    {
        InitializeLogger(context);

        if (RequiresAuthentication && context.UserId is null)
        {
            await WriteUnauthenticatedResponseAsync(context);
            return default!;
        }

        var result = await CallBackendAsync(context);

        if (!result.IsSuccess)
        {
            await WriteBackendErrorResponseAsync(context, result);
            return default!;
        }

        return TransformResponse(result.Value!, context);
    }

    // Writes a user-facing 401 directly. A missing user identity is a *client* auth failure, not a
    // BFF-to-backend credential failure, so it must not flow through WriteBackendErrorResponseAsync
    // (which remaps backend 401 -> 502).
    private static async Task WriteUnauthenticatedResponseAsync(TransformerContext context)
    {
        context.HttpContext.Response.StatusCode = 401;
        await context.HttpContext.Response.WriteAsJsonAsync(
            new { error = "User not authenticated" },
            context.CancellationToken);
    }
}

/// <summary>
/// A transformer that requires authentication and creates a backend request body automatically.
/// The client sends no request body (e.g., GET endpoint), but the transformer creates one for the backend (e.g., POST with UserId).
/// </summary>
/// <typeparam name="TBackendRequest">The request body type to send to backend</typeparam>
/// <typeparam name="TResponse">The response type from backend</typeparam>
/// <example>
/// public class UserInfoTransformer : AuthenticatedTransformer&lt;BackendUserRequest, UserInfo&gt;
/// {
///     protected override BackendUserRequest CreateBackendRequest(TransformerContext context)
///         =&gt; new() { UserId = context.UserId! };
/// }
/// </example>
public abstract class AuthenticatedTransformer<TBackendRequest, TResponse> : TransformerBase<TResponse>
{
    /// <summary>
    /// Creates the request body to send to the backend.
    /// </summary>
    protected abstract TBackendRequest CreateBackendRequest(TransformerContext context);

    /// <summary>
    /// Optional: Transform the response before returning.
    /// Default implementation returns the response as-is.
    /// </summary>
    protected virtual TResponse TransformResponse(TResponse response, TransformerContext context) => response;

    public override async Task<TResponse> TransformAsync(TransformerContext context)
    {
        InitializeLogger(context);

        if (context.UserId is null)
        {
            context.HttpContext.Response.StatusCode = 401;
            await context.HttpContext.Response.WriteAsJsonAsync(
                new { error = "User not authenticated" },
                context.CancellationToken);
            return default!;
        }

        var backendRequest = CreateBackendRequest(context);
        var result = await CallBackendAsync(backendRequest, context);

        if (!result.IsSuccess)
        {
            await WriteBackendErrorResponseAsync(context, result);
            return default!;
        }

        return TransformResponse(result.Value!, context);
    }
}

/// <summary>
/// A transformer that requires authentication but doesn't send a request body to backend.
/// </summary>
/// <typeparam name="TResponse">The response type from backend</typeparam>
public abstract class AuthenticatedTransformer<TResponse> : PassThroughTransformer<TResponse>
{
    protected sealed override bool RequiresAuthentication => true;
}
