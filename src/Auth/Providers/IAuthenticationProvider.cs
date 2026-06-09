using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Auth.Providers;

/// <summary>
/// Provides authentication context for backend requests.
/// Implement this interface to create custom authentication providers.
/// </summary>
/// <remarks>
/// The library provides two built-in implementations:
/// <list type="bullet">
///   <item><see cref="SessionAuthProvider"/> - Session-based authentication with OIDC tokens</item>
///   <item><see cref="ReferenceTokenAuthProvider"/> - Reference token authentication with introspection</item>
/// </list>
///
/// For custom authentication (API keys, HMAC, custom JWTs, etc.), implement this interface
/// and register using <c>AddPortaAuthProvider&lt;T&gt;()</c>.
/// </remarks>
/// <example>
/// <code>
/// public class ApiKeyAuthProvider : IAuthenticationProvider
/// {
///     public Task&lt;AuthenticationContext&gt; GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
///     {
///         var apiKey = context.Request.Headers["X-Api-Key"].FirstOrDefault();
///         if (string.IsNullOrEmpty(apiKey))
///             return Task.FromResult(new AuthenticationContext());
///
///         // Validate API key...
///         return Task.FromResult(new AuthenticationContext
///         {
///             AccessToken = apiKey,
///             Claims = { ["api_key_id"] = ["key-123"] }
///         });
///     }
///
///     public Task&lt;AuthenticationContext?&gt; RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
///         => Task.FromResult&lt;AuthenticationContext?&gt;(null); // API keys don't refresh
///
///     public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default)
///         => Task.CompletedTask; // Nothing to invalidate
/// }
/// </code>
/// </example>
public interface IAuthenticationProvider
{
    /// <summary>
    /// Stable identifier used by <c>CompositeAuthenticationProvider</c> to route
    /// <see cref="RefreshAsync"/> back to the provider that originally issued an
    /// <see cref="AuthenticationContext"/>. Defaults to the implementation type's
    /// full name so existing custom providers need no changes.
    /// </summary>
    string Scheme => GetType().FullName!;

    /// <summary>
    /// Gets authentication information from the current HTTP context.
    /// Called for each request to establish the authentication context.
    /// </summary>
    /// <param name="context">The HTTP context for the current request</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>
    /// An <see cref="AuthenticationContext"/> containing the user's authentication state.
    /// Returns an empty context (IsAuthenticated = false) if the user is not authenticated.
    /// </returns>
    /// <remarks>
    /// Implementations should:
    /// <list type="bullet">
    ///   <item>Extract tokens/credentials from headers, cookies, or session</item>
    ///   <item>Validate the credentials if necessary</item>
    ///   <item>Populate claims from the validated identity</item>
    ///   <item>Return an empty context for unauthenticated requests (don't throw)</item>
    /// </list>
    /// </remarks>
    Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Attempts to get authentication information, returning an unauthenticated context on failure.
    /// Used for endpoints that allow optional authentication (AllowAnonymousWithOptionalAuth).
    /// </summary>
    /// <param name="context">The HTTP context for the current request</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>
    /// An <see cref="AuthenticationContext"/> containing the user's authentication state if credentials
    /// are present and valid, or an unauthenticated context otherwise.
    /// </returns>
    /// <remarks>
    /// This method differs from <see cref="GetAuthContextAsync"/> in that it:
    /// <list type="bullet">
    ///   <item>Never throws for authentication failures</item>
    ///   <item>Returns an unauthenticated context if credentials are invalid or expired</item>
    ///   <item>Is suitable for endpoints where authentication enhances but is not required</item>
    ///   <item>Still propagates <see cref="OperationCanceledException"/> for genuine request cancellation, rather than masking a dead request as unauthenticated</item>
    /// </list>
    /// Default implementation wraps <see cref="GetAuthContextAsync"/> in a try-catch that excludes cancellation.
    /// </remarks>
    async Task<AuthenticationContext> TryGetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            return await GetAuthContextAsync(context, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return AuthenticationContext.Unauthenticated();
        }
    }

    /// <summary>
    /// Refreshes the authentication context when tokens are expired or about to expire.
    /// </summary>
    /// <param name="current">The current authentication context to refresh</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>
    /// A new <see cref="AuthenticationContext"/> with refreshed tokens, or null if refresh failed.
    /// </returns>
    /// <remarks>
    /// Implementations should:
    /// <list type="bullet">
    ///   <item>Use refresh tokens to obtain new access tokens</item>
    ///   <item>Return null if refresh is not supported or failed</item>
    ///   <item>Update token storage if tokens are persisted</item>
    /// </list>
    /// For providers that don't support refresh (e.g., API keys), return null.
    /// </remarks>
    Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidates authentication for the current context (logout).
    /// </summary>
    /// <param name="context">The HTTP context for the current request</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>A task representing the async operation</returns>
    /// <remarks>
    /// Implementations should:
    /// <list type="bullet">
    ///   <item>Clear any stored tokens from session/cache</item>
    ///   <item>Invalidate cached introspection results</item>
    ///   <item>Not throw if there's nothing to invalidate</item>
    /// </list>
    /// </remarks>
    Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default);
}
