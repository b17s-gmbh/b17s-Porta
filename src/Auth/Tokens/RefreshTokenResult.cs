namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Why a token refresh did not produce a new token. Lets callers distinguish a
/// dead session (the refresh token itself was rejected — sign the user out) from
/// a transient hiccup (keep serving the current token and retry later).
/// </summary>
public enum RefreshFailureReason
{
    /// <summary>The refresh succeeded; there is no failure.</summary>
    None = 0,

    /// <summary>
    /// The authorization server rejected the refresh token itself (OAuth2
    /// <c>invalid_grant</c>, RFC 6749 §5.2): it was revoked, has expired, or was
    /// rotated out. The session cannot be recovered by retrying — the caller should
    /// sign the user out / return 401 rather than reuse the current access token.
    /// </summary>
    InvalidGrant = 1,

    /// <summary>
    /// A transient or indeterminate failure (network error, 5xx, timeout, missing
    /// configuration, or an unparseable response). The refresh token may still be
    /// valid, so the caller may keep serving the current token and retry later.
    /// </summary>
    Transient = 2,
}

/// <summary>
/// Outcome of a token refresh: either the rotated tokens, or a classified failure
/// reason. Replaces the previous "null on any failure" contract so callers can tell
/// a revoked/expired refresh token apart from a transient outage.
/// </summary>
public readonly struct RefreshTokenResult
{
    private RefreshTokenResult(TokenExchangeResponse? response, RefreshFailureReason reason)
    {
        Response = response;
        Reason = reason;
    }

    /// <summary>The rotated tokens when the refresh succeeded; otherwise <see langword="null"/>.</summary>
    public TokenExchangeResponse? Response { get; }

    /// <summary>Why the refresh failed, or <see cref="RefreshFailureReason.None"/> on success.</summary>
    public RefreshFailureReason Reason { get; }

    /// <summary>Whether the refresh produced a usable token response.</summary>
    public bool IsSuccess => Response is not null;

    /// <summary>
    /// Whether the failure means the session is dead — the refresh token is no longer
    /// valid at the authorization server and retrying cannot help.
    /// </summary>
    public bool IsInvalidGrant => Reason == RefreshFailureReason.InvalidGrant;

    /// <summary>Creates a successful result carrying the rotated <paramref name="response"/>.</summary>
    public static RefreshTokenResult Success(TokenExchangeResponse response) => new(response, RefreshFailureReason.None);

    /// <summary>Creates a failure result indicating the refresh token was rejected (<c>invalid_grant</c>).</summary>
    public static RefreshTokenResult InvalidGrant() => new(null, RefreshFailureReason.InvalidGrant);

    /// <summary>Creates a failure result indicating a transient/indeterminate failure.</summary>
    public static RefreshTokenResult Transient() => new(null, RefreshFailureReason.Transient);
}
