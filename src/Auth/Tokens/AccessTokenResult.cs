namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Outcome of <see cref="IAccessTokenRefreshService.GetAccessTokenAsync"/>: either the current
/// access token (possibly <c>null</c> when the request is unauthenticated or the ticket carries
/// no token), or the signal that the session was terminated because the IdP rejected the refresh
/// token (<c>invalid_grant</c>).
/// </summary>
/// <remarks>
/// The distinction exists for fail-closed behavior: when <see cref="SessionTerminated"/> is
/// <see langword="true"/>, the (already signed-out) cookie ticket may still hold the old access
/// token for the remainder of the request, but callers must treat the request as unauthenticated
/// rather than fall back to that stale token — otherwise a revoked session keeps working until
/// its access token expires.
/// </remarks>
public readonly record struct AccessTokenResult
{
    /// <summary>
    /// The current (possibly just-rotated) access token, or <c>null</c> when none is available.
    /// Always <c>null</c> when <see cref="SessionTerminated"/> is <see langword="true"/>.
    /// </summary>
    public string? AccessToken { get; private init; }

    /// <summary>
    /// <see langword="true"/> when the IdP rejected the refresh token (<c>invalid_grant</c>) and
    /// the session has been signed out. Callers must treat the request as unauthenticated and must
    /// not fall back to the ticket's stale access token.
    /// </summary>
    public bool SessionTerminated { get; private init; }

    /// <summary>A result carrying no token: the request is unauthenticated or the ticket holds no access token.</summary>
    public static AccessTokenResult None => default;

    /// <summary>Creates a result carrying the given access token (equivalent to <see cref="None"/> when <c>null</c>).</summary>
    /// <param name="accessToken">The current access token, or <c>null</c> when none is available.</param>
    public static AccessTokenResult FromToken(string? accessToken) => new() { AccessToken = accessToken };

    /// <summary>Creates the fail-closed result: the refresh token was rejected and the session has been signed out.</summary>
    public static AccessTokenResult SignedOut() => new() { SessionTerminated = true };
}
