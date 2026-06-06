namespace b17s.Porta.Auth.Sessions;

/// <summary>
/// Information about an active session
/// </summary>
public sealed class SessionInfo
{
    /// <summary>
    /// Unique session identifier
    /// </summary>
    public string SessionId { get; set; } = string.Empty;

    /// <summary>
    /// User identifier (sub claim)
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// User's email address
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// When the session was created
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Last activity time
    /// </summary>
    public DateTimeOffset LastActivity { get; set; }

    /// <summary>
    /// When the session expires
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>
    /// IP address of the client
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent string
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Refresh token protected via IDataProtector. Used by force-revoke flows
    /// (admin termination, back-channel logout) to call the IdP's RFC 7009
    /// revocation endpoint. Null when no refresh token was issued or when the
    /// session was created via a non-OIDC flow.
    /// </summary>
    public string? EncryptedRefreshToken { get; set; }
}
