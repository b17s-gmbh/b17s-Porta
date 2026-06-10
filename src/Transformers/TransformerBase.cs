using System.Diagnostics.CodeAnalysis;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;

namespace b17s.Porta.Transformers;

/// <summary>
/// Base class for transformers with helper methods for common operations.
/// </summary>
/// <typeparam name="TRequest">The request body type</typeparam>
/// <typeparam name="TResponse">The response body type</typeparam>
public abstract class TransformerBase<TRequest, TResponse> : ITransformer<TRequest, TResponse>
{
    /// <summary>
    /// Logger instance for use by derived transformers.
    /// </summary>
    // Defaults to NullLogger so transformer helpers (GetRequiredClaim, LogBackendCallFailed, the
    // error writers) never NRE if used before InitializeLogger runs. The framework calls
    // InitializeLogger before TransformAsync (see TransformerEndpointBuilder), so inside a normal
    // request this is always the real logger.
    protected ILogger Logger { get; private set; } = NullLogger.Instance;

    /// <summary>
    /// Transforms the incoming request into the response. Implementations call the configured
    /// backend(s) (e.g. via <see cref="CallBackendAsync(TRequest, TransformerContext)"/>) and shape
    /// the result, or write an error response directly to the HTTP context.
    /// </summary>
    /// <param name="request">
    /// The deserialized request body, or <see langword="null"/> when the incoming request carried no
    /// JSON body.
    /// </param>
    /// <param name="context">The transformer context for the current request.</param>
    /// <returns>The response to serialize to the client.</returns>
    public abstract Task<TResponse> TransformAsync(TRequest? request, TransformerContext context);

    /// <summary>
    /// Sets the logger from the context. The framework calls this before <c>TransformAsync</c>;
    /// until then <see cref="Logger"/> is a no-op <c>NullLogger</c>.
    /// </summary>
    protected internal void InitializeLogger(TransformerContext context) => Logger = context.Logger;

    /// <summary>
    /// Calls the configured backend with the request.
    /// Uses the backend configuration from the endpoint builder.
    /// </summary>
    protected async Task<BackendResult<TResponse>> CallBackendAsync(TRequest? request, TransformerContext context)
    {
        InitializeLogger(context);
        if (!TryGetBackendRequest(context, out var backendRequest))
        {
            return BackendResult<TResponse>.Failure(500, "Backend request configuration not found in context", BackendErrorType.Unknown);
        }

        if (request == null)
        {
            return await context.BackendCaller.CallAsync<TResponse>(backendRequest, context.CancellationToken);
        }

        return await context.BackendCaller.CallAsync<TRequest, TResponse>(backendRequest, request, context.CancellationToken);
    }

    /// <summary>
    /// Logs that a backend call failed in parallel execution.
    /// </summary>
    protected void LogBackendCallFailed(Exception ex) => TransformerLogging.BackendCallFailed(Logger, ex);

    /// <summary>
    /// Calls the configured backend with a modified request.
    /// </summary>
    protected async Task<BackendResult<TResponse>> CallBackendAsync<TModifiedRequest>(TModifiedRequest modifiedRequest, TransformerContext context)
    {
        if (!TryGetBackendRequest(context, out var backendRequest))
        {
            return BackendResult<TResponse>.Failure(500, "Backend request configuration not found in context", BackendErrorType.Unknown);
        }
        return await context.BackendCaller.CallAsync<TModifiedRequest, TResponse>(backendRequest, modifiedRequest, context.CancellationToken);
    }

    /// <summary>
    /// Calls a different backend URL (overrides the configured one).
    /// </summary>
    protected async Task<BackendResult<TResponse>> CallBackendAsync(TRequest? request, TransformerContext context, string backendUrl)
    {
        if (!TryGetBackendRequest(context, out var backendRequest))
        {
            return BackendResult<TResponse>.Failure(500, "Backend request configuration not found in context", BackendErrorType.Unknown);
        }
        backendRequest = backendRequest with { Url = backendUrl };

        if (request == null)
        {
            return await context.BackendCaller.CallAsync<TResponse>(backendRequest, context.CancellationToken);
        }

        return await context.BackendCaller.CallAsync<TRequest, TResponse>(backendRequest, request, context.CancellationToken);
    }

    /// <summary>
    /// Gets the first value of a claim from the authentication context, or null if absent.
    /// For a claim type that may carry multiple values, use <see cref="GetClaims"/>.
    /// </summary>
    protected string? GetClaim(TransformerContext context, string claimType)
        => context.AuthContext.Claims.TryGetValue(claimType, out var values) && values.Length > 0 ? values[0] : null;

    /// <summary>
    /// Gets every value of a claim from the authentication context (e.g. multiple role claims),
    /// or an empty list when the claim is absent.
    /// </summary>
    protected static IReadOnlyList<string> GetClaims(TransformerContext context, string claimType)
        => context.AuthContext.Claims.TryGetValue(claimType, out var values) ? values : [];

    /// <summary>
    /// Gets a required claim value, returning null if not found.
    /// Callers should check for null and write an appropriate error response to context.HttpContext.Response.
    /// </summary>
    /// <returns>The claim value, or null if not found</returns>
    protected string? GetRequiredClaim(TransformerContext context, string claimType)
    {
        var value = GetClaim(context, claimType);
        if (string.IsNullOrEmpty(value))
        {
            TransformerLogging.RequiredClaimNotFound(Logger, claimType);
            return null;
        }
        return value;
    }

    /// <summary>
    /// Gets a route parameter value.
    /// </summary>
    protected string? GetRouteValue(TransformerContext context, string key)
        => context.RouteValues.TryGetValue(key, out var value) ? value?.ToString() : null;

    /// <summary>
    /// Gets a query parameter value (first value if multiple exist).
    /// </summary>
    protected string? GetQueryParameter(TransformerContext context, string key)
        => context.QueryParameters.TryGetValue(key, out var value) ? (value.Count > 0 ? value[0] : null) : null;

    /// <summary>
    /// Gets all values for a multi-value query parameter.
    /// Example: ?tags=a&amp;tags=b&amp;tags=c returns ["a", "b", "c"]
    /// </summary>
    protected IEnumerable<string> GetQueryValues(TransformerContext context, string key)
    {
        if (context.QueryParameters.TryGetValue(key, out var value))
        {
            return value.ToArray().Where(v => v != null).Select(v => v!);
        }
        return [];
    }

    /// <summary>
    /// Gets a request header value (first value if multiple exist).
    /// </summary>
    protected string? GetRequestHeader(TransformerContext context, string headerName)
        => context.RequestHeaders.TryGetValue(headerName, out var value) ? (value.Count > 0 ? value[0] : null) : null;

    /// <summary>
    /// Gets all values for a multi-value request header.
    /// </summary>
    protected IEnumerable<string> GetRequestHeaders(TransformerContext context, string headerName)
    {
        if (context.RequestHeaders.TryGetValue(headerName, out var value))
        {
            return value.ToArray().Where(v => v != null).Select(v => v!);
        }
        return [];
    }

    /// <summary>
    /// Sets a response header value, replacing any existing value.
    /// </summary>
    protected void SetResponseHeader(TransformerContext context, string name, string value)
        => context.HttpContext.Response.Headers[name] = value;

    /// <summary>
    /// Adds a value to a response header (appends if header already exists).
    /// </summary>
    protected void AddResponseHeader(TransformerContext context, string name, string value)
        => context.HttpContext.Response.Headers.Append(name, value);

    /// <summary>
    /// Removes a response header.
    /// </summary>
    protected void RemoveResponseHeader(TransformerContext context, string name)
        => context.HttpContext.Response.Headers.Remove(name);

    /// <summary>
    /// Writes an error response to the HTTP context using the author-chosen status code, verbatim.
    /// Use this instead of throwing exceptions to avoid 500 errors and improve performance.
    /// </summary>
    /// <param name="context">The transformer context</param>
    /// <param name="statusCode">HTTP status code (e.g., 400 for Bad Request, 401 for Unauthorized). Written unchanged.</param>
    /// <param name="errorMessage">Error message to return to the client</param>
    /// <remarks>
    /// This is the general-purpose writer: the status you pass is sent as-is, so a transformer can
    /// emit a genuine user-facing 401/403. The backend 401/403 -> 502 remap (and backend 5xx detail
    /// masking) lives only in <see cref="WriteBackendErrorResponseAsync{T}"/>, the one path that
    /// relays a backend status. No-op if the response has already started.
    /// </remarks>
    protected async Task WriteErrorResponseAsync(TransformerContext context, int statusCode, string errorMessage)
    {
        if (context.HttpContext.Response.HasStarted)
        {
            // The status line is already committed; setting StatusCode now would throw
            // InvalidOperationException. Bail cleanly, matching the raw-forward handler's guard.
            TransformerLogging.ErrorResponseAfterStart(Logger, statusCode);
            return;
        }

        context.HttpContext.Response.StatusCode = statusCode;
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = errorMessage
        }, context.CancellationToken);
    }

    /// <summary>
    /// Writes a backend result as a client error response. Backend 401/403 are remapped to 502
    /// (a backend auth failure is a BFF-credential problem, not the user's session expiring, so the
    /// client must not sign the user out), and backend 5xx error text is logged server-side only -
    /// the client receives a generic message rather than raw backend detail (which can echo reason
    /// phrases or deserializer output).
    /// </summary>
    protected async Task WriteBackendErrorResponseAsync<T>(TransformerContext context, BackendResult<T> result)
    {
        var (clientStatus, clientMessage) = result.StatusCode switch
        {
            401 => (502, "Backend service authentication failed"),
            403 => (502, "Backend service authorization failed"),
            >= 500 => (result.StatusCode, "Backend service error"),
            _ => (result.StatusCode, result.Error ?? "Backend request failed")
        };

        // Keep backend-internal detail out of the client response; record it server-side so a 5xx
        // is still diagnosable.
        if (result.StatusCode >= 500 && !string.IsNullOrEmpty(result.Error))
        {
            TransformerLogging.BackendErrorMasked(Logger, result.StatusCode, result.Error);
        }

        await WriteErrorResponseAsync(context, clientStatus, clientMessage);
    }

    /// <summary>
    /// Writes a failed <see cref="GraphQLResult{TData}"/> as a client error response, surfacing the
    /// GraphQL-mapped status (e.g. 404 for <c>NOT_FOUND</c>, 401 for <c>UNAUTHENTICATED</c>,
    /// 403 for <c>FORBIDDEN</c>) verbatim. Prefer this over
    /// <see cref="WriteBackendErrorResponseAsync{T}"/> for GraphQL results: an application-level
    /// GraphQL auth error arrives over HTTP 200 and is the user's authorization being denied, so it
    /// must reach the client as the documented 401/403, not the 502 that
    /// <see cref="WriteBackendErrorResponseAsync{T}"/> applies to a backend-credential failure.
    /// (A transport-level backend 401/403 - even one carrying an <c>errors</c> envelope - is already
    /// routed through the backend error mapper, by default neutralized to 502, before it ever
    /// becomes a <see cref="GraphQLResult{TData}"/>.) Mapped 5xx error text is logged
    /// server-side only and replaced with a generic message, matching the backend writer.
    /// </summary>
    /// <typeparam name="TData">The GraphQL data type.</typeparam>
    /// <param name="context">The transformer context.</param>
    /// <param name="result">The failed GraphQL result to relay.</param>
    protected async Task WriteGraphQLErrorResponseAsync<TData>(TransformerContext context, GraphQLResult<TData> result)
    {
        var (clientStatus, clientMessage) = result.MappedStatusCode switch
        {
            >= 500 => (result.MappedStatusCode, "Backend service error"),
            _ => (result.MappedStatusCode, result.Error ?? "GraphQL request failed")
        };

        // Mapped 5xx detail can echo backend/deserializer text; keep it server-side only.
        if (result.MappedStatusCode >= 500 && !string.IsNullOrEmpty(result.Error))
        {
            TransformerLogging.BackendErrorMasked(Logger, result.MappedStatusCode, result.Error);
        }

        await WriteErrorResponseAsync(context, clientStatus, clientMessage);
    }

    private static bool TryGetBackendRequest(TransformerContext context, [NotNullWhen(true)] out BackendRequest? backendRequest)
    {
        if (context.Properties.TryGetValue("BackendRequest", out var obj) && obj is BackendRequest request)
        {
            backendRequest = request;
            return true;
        }

        backendRequest = null;
        return false;
    }
}

/// <summary>
/// Base class for transformers with helper methods for common operations.
/// </summary>
/// <typeparam name="TResponse">The response body type</typeparam>
public abstract class TransformerBase<TResponse> : ITransformer<TResponse>
{
    /// <summary>
    /// Logger instance for use by derived transformers.
    /// </summary>
    // Defaults to NullLogger so transformer helpers (GetRequiredClaim, LogBackendCallFailed, the
    // error writers) never NRE if used before InitializeLogger runs. The framework calls
    // InitializeLogger before TransformAsync (see TransformerEndpointBuilder), so inside a normal
    // request this is always the real logger.
    protected ILogger Logger { get; private set; } = NullLogger.Instance;

    /// <summary>
    /// Transforms the current request into the response. Implementations call the configured
    /// backend(s) (e.g. via <see cref="CallBackendAsync(TransformerContext)"/>) and shape the result,
    /// or write an error response directly to the HTTP context. This overload ignores any request
    /// body.
    /// </summary>
    /// <param name="context">The transformer context for the current request.</param>
    /// <returns>The response to serialize to the client.</returns>
    public abstract Task<TResponse> TransformAsync(TransformerContext context);

    /// <summary>
    /// Sets the logger from the context. The framework calls this before <c>TransformAsync</c>;
    /// until then <see cref="Logger"/> is a no-op <c>NullLogger</c>.
    /// </summary>
    protected internal void InitializeLogger(TransformerContext context)
        => Logger = context.Logger;

    /// <summary>
    /// Calls the configured backend with the request.
    /// Uses the backend configuration from the endpoint builder.
    /// </summary>
    protected async Task<BackendResult<TResponse>> CallBackendAsync(TransformerContext context)
    {
        InitializeLogger(context);
        if (!TryGetBackendRequest(context, out var backendRequest))
        {
            return BackendResult<TResponse>.Failure(500, "Backend request configuration not found in context", BackendErrorType.Unknown);
        }

        return await context.BackendCaller.CallAsync<TResponse>(backendRequest, context.CancellationToken);
    }

    /// <summary>
    /// Logs that a backend call failed in parallel execution.
    /// </summary>
    protected void LogBackendCallFailed(Exception ex)
        => TransformerLogging.BackendCallFailed(Logger, ex);

    /// <summary>
    /// Calls the configured backend with a modified request.
    /// </summary>
    protected async Task<BackendResult<TResponse>> CallBackendAsync<TModifiedRequest>(TModifiedRequest modifiedRequest, TransformerContext context)
    {
        if (!TryGetBackendRequest(context, out var backendRequest))
        {
            return BackendResult<TResponse>.Failure(500, "Backend request configuration not found in context", BackendErrorType.Unknown);
        }
        return await context.BackendCaller.CallAsync<TModifiedRequest, TResponse>(backendRequest, modifiedRequest, context.CancellationToken);
    }

    /// <summary>
    /// Calls a different backend URL (overrides the configured one).
    /// </summary>
    protected async Task<BackendResult<TResponse>> CallBackendAsync(TransformerContext context, string backendUrl)
    {
        if (!TryGetBackendRequest(context, out var backendRequest))
        {
            return BackendResult<TResponse>.Failure(500, "Backend request configuration not found in context", BackendErrorType.Unknown);
        }
        backendRequest = backendRequest with { Url = backendUrl };

        return await context.BackendCaller.CallAsync<TResponse>(backendRequest, context.CancellationToken);
    }

    /// <summary>
    /// Gets the first value of a claim from the authentication context, or null if absent.
    /// For a claim type that may carry multiple values, use <see cref="GetClaims"/>.
    /// </summary>
    protected string? GetClaim(TransformerContext context, string claimType)
        => context.AuthContext.Claims.TryGetValue(claimType, out var values) && values.Length > 0 ? values[0] : null;

    /// <summary>
    /// Gets every value of a claim from the authentication context (e.g. multiple role claims),
    /// or an empty list when the claim is absent.
    /// </summary>
    protected static IReadOnlyList<string> GetClaims(TransformerContext context, string claimType)
        => context.AuthContext.Claims.TryGetValue(claimType, out var values) ? values : [];

    /// <summary>
    /// Gets a required claim value, returning null if not found.
    /// Callers should check for null and write an appropriate error response to context.HttpContext.Response.
    /// </summary>
    /// <returns>The claim value, or null if not found</returns>
    protected string? GetRequiredClaim(TransformerContext context, string claimType)
    {
        var value = GetClaim(context, claimType);
        if (string.IsNullOrEmpty(value))
        {
            TransformerLogging.RequiredClaimNotFound(Logger, claimType);
            return null;
        }
        return value;
    }

    /// <summary>
    /// Gets a route parameter value.
    /// </summary>
    protected string? GetRouteValue(TransformerContext context, string key)
        => context.RouteValues.TryGetValue(key, out var value) ? value?.ToString() : null;

    /// <summary>
    /// Gets a query parameter value (first value if multiple exist).
    /// </summary>
    protected string? GetQueryParameter(TransformerContext context, string key)
        => context.QueryParameters.TryGetValue(key, out var value) ? (value.Count > 0 ? value[0] : null) : null;

    /// <summary>
    /// Gets all values for a multi-value query parameter.
    /// Example: ?tags=a&amp;tags=b&amp;tags=c returns ["a", "b", "c"]
    /// </summary>
    protected IEnumerable<string> GetQueryValues(TransformerContext context, string key)
    {
        if (context.QueryParameters.TryGetValue(key, out var value))
        {
            return value.ToArray().Where(v => v != null).Select(v => v!);
        }
        return [];
    }

    /// <summary>
    /// Gets a request header value (first value if multiple exist).
    /// </summary>
    protected string? GetRequestHeader(TransformerContext context, string headerName)
        => context.RequestHeaders.TryGetValue(headerName, out var value) ? (value.Count > 0 ? value[0] : null) : null;

    /// <summary>
    /// Gets all values for a multi-value request header.
    /// </summary>
    protected IEnumerable<string> GetRequestHeaders(TransformerContext context, string headerName)
    {
        if (context.RequestHeaders.TryGetValue(headerName, out var value))
        {
            return value.ToArray().Where(v => v != null).Select(v => v!);
        }
        return [];
    }

    /// <summary>
    /// Sets a response header value, replacing any existing value.
    /// </summary>
    protected void SetResponseHeader(TransformerContext context, string name, string value)
        => context.HttpContext.Response.Headers[name] = value;

    /// <summary>
    /// Adds a value to a response header (appends if header already exists).
    /// </summary>
    protected void AddResponseHeader(TransformerContext context, string name, string value)
        => context.HttpContext.Response.Headers.Append(name, value);

    /// <summary>
    /// Removes a response header.
    /// </summary>
    protected void RemoveResponseHeader(TransformerContext context, string name)
        => context.HttpContext.Response.Headers.Remove(name);

    /// <summary>
    /// Writes an error response to the HTTP context using the author-chosen status code, verbatim.
    /// Use this instead of throwing exceptions to avoid 500 errors and improve performance.
    /// </summary>
    /// <param name="context">The transformer context</param>
    /// <param name="statusCode">HTTP status code (e.g., 400 for Bad Request, 401 for Unauthorized). Written unchanged.</param>
    /// <param name="errorMessage">Error message to return to the client</param>
    /// <remarks>
    /// This is the general-purpose writer: the status you pass is sent as-is, so a transformer can
    /// emit a genuine user-facing 401/403. The backend 401/403 -> 502 remap (and backend 5xx detail
    /// masking) lives only in <see cref="WriteBackendErrorResponseAsync{T}"/>, the one path that
    /// relays a backend status. No-op if the response has already started.
    /// </remarks>
    protected async Task WriteErrorResponseAsync(TransformerContext context, int statusCode, string errorMessage)
    {
        if (context.HttpContext.Response.HasStarted)
        {
            // The status line is already committed; setting StatusCode now would throw
            // InvalidOperationException. Bail cleanly, matching the raw-forward handler's guard.
            TransformerLogging.ErrorResponseAfterStart(Logger, statusCode);
            return;
        }

        context.HttpContext.Response.StatusCode = statusCode;
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = errorMessage
        }, context.CancellationToken);
    }

    /// <summary>
    /// Writes a backend result as a client error response. Backend 401/403 are remapped to 502
    /// (a backend auth failure is a BFF-credential problem, not the user's session expiring, so the
    /// client must not sign the user out), and backend 5xx error text is logged server-side only -
    /// the client receives a generic message rather than raw backend detail (which can echo reason
    /// phrases or deserializer output).
    /// </summary>
    protected async Task WriteBackendErrorResponseAsync<T>(TransformerContext context, BackendResult<T> result)
    {
        var (clientStatus, clientMessage) = result.StatusCode switch
        {
            401 => (502, "Backend service authentication failed"),
            403 => (502, "Backend service authorization failed"),
            >= 500 => (result.StatusCode, "Backend service error"),
            _ => (result.StatusCode, result.Error ?? "Backend request failed")
        };

        // Keep backend-internal detail out of the client response; record it server-side so a 5xx
        // is still diagnosable.
        if (result.StatusCode >= 500 && !string.IsNullOrEmpty(result.Error))
        {
            TransformerLogging.BackendErrorMasked(Logger, result.StatusCode, result.Error);
        }

        await WriteErrorResponseAsync(context, clientStatus, clientMessage);
    }

    /// <summary>
    /// Writes a failed <see cref="GraphQLResult{TData}"/> as a client error response, surfacing the
    /// GraphQL-mapped status (e.g. 404 for <c>NOT_FOUND</c>, 401 for <c>UNAUTHENTICATED</c>,
    /// 403 for <c>FORBIDDEN</c>) verbatim. Prefer this over
    /// <see cref="WriteBackendErrorResponseAsync{T}"/> for GraphQL results: an application-level
    /// GraphQL auth error arrives over HTTP 200 and is the user's authorization being denied, so it
    /// must reach the client as the documented 401/403, not the 502 that
    /// <see cref="WriteBackendErrorResponseAsync{T}"/> applies to a backend-credential failure.
    /// (A transport-level backend 401/403 - even one carrying an <c>errors</c> envelope - is already
    /// routed through the backend error mapper, by default neutralized to 502, before it ever
    /// becomes a <see cref="GraphQLResult{TData}"/>.) Mapped 5xx error text is logged
    /// server-side only and replaced with a generic message, matching the backend writer.
    /// </summary>
    /// <typeparam name="TData">The GraphQL data type.</typeparam>
    /// <param name="context">The transformer context.</param>
    /// <param name="result">The failed GraphQL result to relay.</param>
    protected async Task WriteGraphQLErrorResponseAsync<TData>(TransformerContext context, GraphQLResult<TData> result)
    {
        var (clientStatus, clientMessage) = result.MappedStatusCode switch
        {
            >= 500 => (result.MappedStatusCode, "Backend service error"),
            _ => (result.MappedStatusCode, result.Error ?? "GraphQL request failed")
        };

        // Mapped 5xx detail can echo backend/deserializer text; keep it server-side only.
        if (result.MappedStatusCode >= 500 && !string.IsNullOrEmpty(result.Error))
        {
            TransformerLogging.BackendErrorMasked(Logger, result.MappedStatusCode, result.Error);
        }

        await WriteErrorResponseAsync(context, clientStatus, clientMessage);
    }

    private static bool TryGetBackendRequest(TransformerContext context, [NotNullWhen(true)] out BackendRequest? backendRequest)
    {
        if (context.Properties.TryGetValue("BackendRequest", out var obj) && obj is BackendRequest request)
        {
            backendRequest = request;
            return true;
        }

        backendRequest = null;
        return false;
    }
}

/// <summary>
/// High-performance logging for transformers using compile-time source generators.
/// EventId range 14050-14059 is reserved for this category; 14000-14017 belongs to
/// <see cref="BackendCaller"/> so EventId-based filtering can tell them apart.
/// </summary>
internal static partial class TransformerLogging
{
    [LoggerMessage(
        EventId = 14050,
        Level = LogLevel.Warning,
        Message = "Backend call failed in parallel execution")]
    public static partial void BackendCallFailed(ILogger logger, Exception ex);

    [LoggerMessage(
        EventId = 14051,
        Level = LogLevel.Warning,
        Message = "Required claim '{ClaimType}' not found in authentication context")]
    public static partial void RequiredClaimNotFound(ILogger logger, string claimType);

    [LoggerMessage(
        EventId = 14052,
        Level = LogLevel.Debug,
        Message = "Observed sibling backend task fault ({ExceptionType}) after the first failure cancelled the parallel batch; original exception is rethrown")]
    public static partial void SiblingTaskFaultObserved(ILogger logger, string exceptionType);

    [LoggerMessage(
        EventId = 14053,
        Level = LogLevel.Warning,
        Message = "WriteErrorResponseAsync called after the response had already started; status {StatusCode} was not written")]
    public static partial void ErrorResponseAfterStart(ILogger logger, int statusCode);

    [LoggerMessage(
        EventId = 14054,
        Level = LogLevel.Warning,
        Message = "Backend returned {StatusCode}; detail masked from the client response: {Error}")]
    public static partial void BackendErrorMasked(ILogger logger, int statusCode, string error);

    [LoggerMessage(
        EventId = 14055,
        Level = LogLevel.Warning,
        Message = "Backend call failed in parallel execution ({ExceptionType}); result coerced to null. Type only - exception messages can carry URLs/secrets")]
    public static partial void BackendCallFailedSafe(ILogger logger, string exceptionType);
}
