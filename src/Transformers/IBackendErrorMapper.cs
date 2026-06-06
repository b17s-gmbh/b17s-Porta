namespace b17s.Porta.Transformers;

/// <summary>
/// Abstraction for mapping backend error responses to client responses.
/// The default implementation maps backend 401/403 to 502 Bad Gateway to prevent
/// clients from misinterpreting backend auth failures as user session expiration.
/// </summary>
/// <remarks>
/// <para>
/// Why the default 401→502 mapping?
/// </para>
/// <para>
/// When a backend returns 401/403, it typically means the BFF's credentials to that
/// backend are misconfigured (wrong API key, expired service account, etc.), NOT that
/// the user's session is invalid. If we pass 401 to the client, the frontend might
/// sign out the user, which is incorrect behavior.
/// </para>
/// <para>
/// To customize this behavior, implement your own <see cref="IBackendErrorMapper"/>:
/// <code>
/// public class MyErrorMapper : IBackendErrorMapper
/// {
///     public (int StatusCode, string Message) MapError(int backendStatusCode, string? backendError, BackendRequest request)
///     {
///         // Pass through auth errors for specific backends
///         if (request.Url.Contains("trusted-internal-api"))
///             return (backendStatusCode, backendError ?? "Request failed");
///
///         // Default behavior for other backends
///         return backendStatusCode switch
///         {
///             401 => (502, "Backend service authentication failed"),
///             403 => (502, "Backend service authorization failed"),
///             _ => (backendStatusCode, backendError ?? "Request failed")
///         };
///     }
/// }
///
/// // Registration
/// services.AddSingleton&lt;IBackendErrorMapper, MyErrorMapper&gt;();
/// </code>
/// </para>
/// </remarks>
public interface IBackendErrorMapper
{
    /// <summary>
    /// Maps a backend error to a client-facing status code and message.
    /// </summary>
    /// <param name="backendStatusCode">The HTTP status code from the backend</param>
    /// <param name="backendError">The error message from the backend (may be null)</param>
    /// <param name="request">The backend request that failed</param>
    /// <returns>A tuple of (StatusCode, Message) to return to the client</returns>
    (int StatusCode, string Message) MapError(int backendStatusCode, string? backendError, BackendRequest request);
}

/// <summary>
/// Default error mapper that maps backend 401/403 errors to 502 Bad Gateway.
/// This prevents clients from misinterpreting backend auth failures as user session expiration.
/// </summary>
public sealed class DefaultBackendErrorMapper : IBackendErrorMapper
{
    /// <inheritdoc />
    public (int StatusCode, string Message) MapError(int backendStatusCode, string? backendError, BackendRequest request)
    {
        // Map backend authentication/authorization errors to 502 Bad Gateway
        // A 401/403 from backend means the BFF's credentials to backend are wrong,
        // NOT that the user's session is invalid. Passing 401 to client would cause
        // the frontend to sign out the user, which is incorrect behavior.
        return backendStatusCode switch
        {
            401 => (502, "Backend service authentication failed"),
            403 => (502, "Backend service authorization failed"),
            _ => (backendStatusCode, backendError ?? "Backend request failed")
        };
    }
}

/// <summary>
/// Pass-through error mapper that returns backend errors as-is without transformation.
/// Use this when you want backend errors to be passed directly to clients.
/// </summary>
/// <remarks>
/// WARNING: Using this mapper means backend 401/403 errors will be returned directly to clients.
/// This could cause frontends to incorrectly sign out users when the backend auth fails.
/// Only use this for internal/trusted APIs where this behavior is acceptable.
/// </remarks>
public sealed class PassThroughBackendErrorMapper : IBackendErrorMapper
{
    /// <inheritdoc />
    public (int StatusCode, string Message) MapError(int backendStatusCode, string? backendError, BackendRequest request)
        => (backendStatusCode, backendError ?? "Backend request failed");
}
