namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Provider-agnostic configuration for token refresh operations
/// </summary>
public sealed class TokenRefreshOptions
{
    /// <summary>
    /// Token endpoint URL (e.g., from OIDC discovery)
    /// </summary>
    public required string TokenEndpoint { get; init; }

    /// <summary>
    /// Client ID for token refresh authentication
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// Client secret for token refresh authentication
    /// </summary>
    public required string ClientSecret { get; init; }

    /// <summary>
    /// Optional scopes to request during refresh
    /// </summary>
    public string? Scope { get; init; }
}

/// <summary>
/// Provides token refresh functionality for maintaining authentication state.
/// This interface is provider-agnostic - it works with any OAuth2-compliant authorization server.
/// </summary>
public interface ITokenRefreshService
{
    /// <summary>
    /// Refreshes an access token using a refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token to use</param>
    /// <param name="options">Provider-agnostic configuration for the refresh operation</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>
    /// A <see cref="RefreshTokenResult"/> carrying the rotated tokens on success, or a classified
    /// <see cref="RefreshFailureReason"/> on failure so callers can distinguish a revoked/expired
    /// refresh token (<c>invalid_grant</c>) from a transient outage.
    /// </returns>
    Task<RefreshTokenResult> RefreshAsync(string refreshToken, TokenRefreshOptions options, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refreshes an access token using a refresh token with configuration from DI.
    /// This overload uses the default configuration injected into the service.
    /// </summary>
    /// <param name="refreshToken">The refresh token to use</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>
    /// A <see cref="RefreshTokenResult"/> carrying the rotated tokens on success, or a classified
    /// <see cref="RefreshFailureReason"/> on failure so callers can distinguish a revoked/expired
    /// refresh token (<c>invalid_grant</c>) from a transient outage.
    /// </returns>
    Task<RefreshTokenResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);
}
