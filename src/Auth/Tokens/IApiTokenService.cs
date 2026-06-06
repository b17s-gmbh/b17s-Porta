using b17s.Porta.Configuration;

using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Provider-agnostic options for API token caching.
/// Use this when you want to avoid coupling to SessionAuthenticationConfiguration.
/// </summary>
public sealed class ApiTokenCacheOptions
{
    /// <summary>
    /// The session storage key for API access tokens.
    /// Default uses the session key configuration from DI.
    /// </summary>
    public required string CacheKey { get; init; }
}

/// <summary>
/// Provides API-specific token management with caching and refresh capabilities.
/// This interface is provider-agnostic - it works with any token storage implementation.
/// </summary>
public interface IApiTokenService
{
    /// <summary>
    /// Gets or creates an API-specific token for the given configuration.
    /// </summary>
    /// <param name="context">The current HTTP context</param>
    /// <param name="apiConfig">Configuration for the target API</param>
    /// <param name="accessToken">The current access token, or null when no user token is available</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>
    /// The API-specific access token, or <c>null</c> when no token could be obtained.
    /// Callers MUST treat null as a fail-closed signal - forwarding <c>Authorization: Bearer </c>
    /// (with an empty value) is interpreted as anonymous by many backends and would
    /// silently downgrade the user's effective permissions.
    /// </returns>
    Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets or creates an API-specific token with explicit cache options.
    /// </summary>
    /// <param name="context">The current HTTP context</param>
    /// <param name="apiConfig">Configuration for the target API</param>
    /// <param name="accessToken">The current access token, or null when no user token is available</param>
    /// <param name="cacheOptions">Provider-agnostic cache options</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>
    /// The API-specific access token, or <c>null</c> when no token could be obtained.
    /// </returns>
    Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidates cached API tokens for the current user
    /// </summary>
    /// <param name="context">The current HTTP context</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    Task InvalidateApiTokensAsync(HttpContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidates cached API tokens with explicit cache options
    /// </summary>
    /// <param name="context">The current HTTP context</param>
    /// <param name="cacheOptions">Provider-agnostic cache options</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    Task InvalidateApiTokensAsync(HttpContext context, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default);
}
