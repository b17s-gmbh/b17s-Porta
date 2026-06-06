namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Provider-agnostic configuration for token revocation operations
/// </summary>
public sealed class TokenRevocationOptions
{
    /// <summary>
    /// Revocation endpoint URL (e.g., from OIDC discovery or manual configuration)
    /// </summary>
    public required string RevocationEndpoint { get; init; }

    /// <summary>
    /// Client ID for revocation authentication
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// Client secret for revocation authentication
    /// </summary>
    public required string ClientSecret { get; init; }
}

/// <summary>
/// Outcome of revoking a single token within a batch operation.
/// </summary>
/// <param name="TokenTypeHint">
/// The <c>token_type_hint</c> supplied for this token (<c>"access_token"</c>, <c>"refresh_token"</c>, or <see langword="null"/>).
/// </param>
/// <param name="Revoked"><see langword="true"/> if the token was revoked (or was already invalid); <see langword="false"/> on error.</param>
public readonly record struct TokenRevocationOutcome(string? TokenTypeHint, bool Revoked);

/// <summary>
/// Aggregated result of a batch token-revocation operation. Reports each token's outcome
/// individually so callers can detect partial failure — in particular whether the refresh
/// token (the long-lived, dangerous credential) was successfully revoked, rather than
/// collapsing the whole batch to a single <see cref="bool"/>.
/// </summary>
public sealed class TokenRevocationBatchResult
{
    /// <summary>
    /// Per-token outcomes, in the order revocation was attempted. Refresh tokens are
    /// attempted first, so an interrupted batch still revokes the most dangerous token.
    /// </summary>
    public required IReadOnlyList<TokenRevocationOutcome> Outcomes { get; init; }

    /// <summary><see langword="true"/> if every token in the batch was successfully revoked.</summary>
    public bool AllRevoked => Outcomes.All(o => o.Revoked);

    /// <summary>
    /// <see langword="true"/> if every token carrying the <c>"refresh_token"</c> hint was revoked.
    /// Vacuously <see langword="true"/> when the batch contained no refresh tokens.
    /// </summary>
    public bool RefreshTokensRevoked => Outcomes.All(o => o.TokenTypeHint != "refresh_token" || o.Revoked);
}

/// <summary>
/// Provides token revocation functionality for invalidating tokens at the authorization server.
/// This interface is provider-agnostic - it works with any OAuth2-compliant authorization server (RFC 7009).
/// </summary>
public interface ITokenRevocationService
{
    /// <summary>
    /// Revokes a token (access or refresh) at the authorization server (RFC 7009)
    /// </summary>
    /// <param name="token">The token to revoke</param>
    /// <param name="options">Provider-agnostic configuration for the revocation operation</param>
    /// <param name="tokenTypeHint">Hint about the token type ("access_token" or "refresh_token")</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>True if revocation succeeded or token was already invalid, false on error</returns>
    Task<bool> RevokeTokenAsync(string token, TokenRevocationOptions options, string? tokenTypeHint = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a token using the default configuration from DI.
    /// </summary>
    /// <param name="token">The token to revoke</param>
    /// <param name="tokenTypeHint">Hint about the token type ("access_token" or "refresh_token")</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>True if revocation succeeded or token was already invalid, false on error</returns>
    Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes multiple tokens (e.g., both access and refresh tokens). Refresh tokens are
    /// attempted first; every token is attempted even if an earlier one fails, so a partial
    /// failure does not leave a more dangerous token live.
    /// </summary>
    /// <param name="options">Provider-agnostic configuration for the revocation operation</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <param name="tokens">Collection of tokens to revoke</param>
    /// <returns>
    /// A <see cref="TokenRevocationBatchResult"/> reporting each token's outcome — inspect
    /// <see cref="TokenRevocationBatchResult.RefreshTokensRevoked"/> to confirm the refresh token is gone.
    /// </returns>
    Task<TokenRevocationBatchResult> RevokeTokensAsync(TokenRevocationOptions options, CancellationToken cancellationToken, params (string Token, string? TokenTypeHint)[] tokens);

    /// <summary>
    /// Revokes multiple tokens using the default configuration from DI. Refresh tokens are
    /// attempted first; every token is attempted even if an earlier one fails.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <param name="tokens">Collection of tokens to revoke</param>
    /// <returns>
    /// A <see cref="TokenRevocationBatchResult"/> reporting each token's outcome — inspect
    /// <see cref="TokenRevocationBatchResult.RefreshTokensRevoked"/> to confirm the refresh token is gone.
    /// </returns>
    Task<TokenRevocationBatchResult> RevokeTokensAsync(CancellationToken cancellationToken, params (string Token, string? TokenTypeHint)[] tokens);
}
