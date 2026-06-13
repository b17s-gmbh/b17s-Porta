namespace b17s.Porta.Auth.Sessions;

/// <summary>
/// Provides session management capabilities for administrators.
/// Sessions are keyed by a per-login identifier - the IdP-issued <c>sid</c> claim when present,
/// otherwise a BFF-generated per-login id - which is shared by the session metadata and the
/// distributed cookie ticket store.
/// </summary>
public interface ISessionManagementService
{
    /// <summary>
    /// Registers a session for admin lookups. Call this after successful authentication
    /// to enable admin session management. The OIDC <c>sub</c> claim is the primary key
    /// (unique, stable, IdP-scoped); email is an optional secondary index used only for
    /// "who's logged in by address" admin queries and only when the IdP attests it is
    /// verified.
    /// </summary>
    /// <param name="sessionId">The per-login session identifier shared by the session metadata and the cookie ticket: the IdP-issued <c>sid</c> claim when present, otherwise a BFF-generated per-login id.</param>
    /// <param name="userId">The user's <c>sub</c> claim - the IdP-scoped subject identifier. Required.</param>
    /// <param name="email">The user's verified email address, or null when the IdP did not assert <c>email_verified=true</c>. Used as a secondary index only.</param>
    /// <param name="ipAddress">Optional client IP address</param>
    /// <param name="userAgent">Optional user agent string</param>
    /// <param name="encryptedRefreshToken">Optional refresh token, already protected via IDataProtector. Required for IdP-side token revocation in force-logout flows.</param>
    Task RegisterSessionAsync(string sessionId, string userId, string? email = null, string? ipAddress = null, string? userAgent = null, string? encryptedRefreshToken = null);

    /// <summary>
    /// Patches the encrypted refresh token stored on the session metadata.
    /// Call this after a refresh-token rotation so subsequent revocations
    /// target the current token, not the rotated-out one.
    /// </summary>
    /// <param name="sessionId">The per-login session identifier (IdP <c>sid</c> or BFF-generated per-login id) the metadata is keyed by.</param>
    /// <param name="encryptedRefreshToken">The new IDataProtector-protected refresh token, or null to clear.</param>
    Task UpdateRefreshTokenAsync(string sessionId, string? encryptedRefreshToken);

    /// <summary>
    /// Encrypts a refresh token for storage on session metadata using the same
    /// protector key that <see cref="TerminateSessionAsync"/> uses to decrypt.
    /// Returns null when data protection is not configured or the input is empty.
    /// </summary>
    string? ProtectRefreshToken(string? refreshToken);

    /// <summary>
    /// Gets all active sessions for a user by email address
    /// </summary>
    /// <param name="email">The user's email address</param>
    /// <param name="cancellationToken">Token to abort the operation when the caller disconnects.</param>
    /// <returns>List of user's active sessions</returns>
    Task<IReadOnlyList<SessionInfo>> GetSessionsByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Terminates a specific session by ID. Termination is idempotent best-effort:
    /// terminating an already-terminated, expired, or never-existing id is not an error.
    /// </summary>
    /// <param name="sessionId">The session identifier</param>
    /// <param name="revokeTokens">Whether to revoke tokens at IdP (best effort)</param>
    /// <param name="cancellationToken">Token to abort the operation when the caller disconnects.</param>
    /// <param name="reason">Low-cardinality cause recorded on the <c>bff.session.invalidated</c> metric's <c>reason</c> tag (e.g. <c>logout</c>, <c>backchannel</c>, <c>admin</c>).</param>
    /// <returns>True when the teardown pass completed - including for ids with no live session; false on invalid input or when teardown failed.</returns>
    Task<bool> TerminateSessionAsync(string sessionId, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified");

    /// <summary>
    /// Terminates all sessions for a user by email address
    /// </summary>
    /// <param name="email">The user's email address</param>
    /// <param name="revokeTokens">Whether to revoke tokens at IdP (best effort)</param>
    /// <param name="cancellationToken">Token to abort the operation when the caller disconnects.</param>
    /// <param name="reason">Low-cardinality cause recorded on the <c>bff.session.invalidated</c> metric's <c>reason</c> tag (e.g. <c>admin</c>).</param>
    /// <returns>Number of sessions terminated</returns>
    Task<int> TerminateSessionsByEmailAsync(string email, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified");

    /// <summary>
    /// Terminates all sessions for a user by subject identifier (the OIDC <c>sub</c> claim).
    /// Used by OIDC back-channel logout when the IdP sends a logout_token containing only
    /// <c>sub</c> (no <c>sid</c>). The <c>sub</c> claim is an opaque IdP-scoped identifier
    /// (typically a UUID) and must NOT be looked up via the email index.
    /// </summary>
    /// <param name="subject">The user's <c>sub</c> claim value as issued by the IdP</param>
    /// <param name="revokeTokens">Whether to revoke tokens at IdP (best effort)</param>
    /// <param name="cancellationToken">Token to abort the operation when the caller disconnects.</param>
    /// <param name="reason">Low-cardinality cause recorded on the <c>bff.session.invalidated</c> metric's <c>reason</c> tag (e.g. <c>backchannel</c>).</param>
    /// <returns>Number of sessions terminated</returns>
    Task<int> TerminateSessionsBySubjectAsync(string subject, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified");

    /// <summary>
    /// Updates the last activity time for a session.
    /// Call this periodically or on significant user activity to track session usage.
    /// </summary>
    /// <param name="sessionId">The per-login session identifier (IdP <c>sid</c> or BFF-generated per-login id) the metadata is keyed by.</param>
    Task TouchSessionAsync(string sessionId);
}
