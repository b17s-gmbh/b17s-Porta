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
    /// The refresh token that pairs with <see cref="AccessToken"/>, or <c>null</c> when the
    /// producing path did not read one off the ticket. The cookie handler caches its
    /// <c>AuthenticateAsync</c> result per request, so after a rotation the request's own
    /// authenticate result still carries the rotated-out refresh token; consumers must use
    /// this value instead of re-reading the ticket.
    /// </summary>
    public string? RefreshToken { get; private init; }

    /// <summary>
    /// The ID token that pairs with <see cref="AccessToken"/>, or <c>null</c> when the
    /// producing path did not read one off the ticket.
    /// </summary>
    public string? IdToken { get; private init; }

    /// <summary>
    /// Expiry of <see cref="AccessToken"/>, or <c>null</c> when the producing path did not
    /// read one off the ticket. After a refresh this is the rotated token's expiry, which the
    /// request's per-request-cached authenticate result cannot observe.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; private init; }

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

    /// <summary>
    /// Creates a result carrying the full token set of the current (possibly just-rotated)
    /// ticket, so callers can build an up-to-date context without re-reading the ticket
    /// through the per-request-cached <c>AuthenticateAsync</c>.
    /// </summary>
    /// <param name="accessToken">The current access token, or <c>null</c> when none is available.</param>
    /// <param name="refreshToken">The refresh token paired with <paramref name="accessToken"/>, or <c>null</c>.</param>
    /// <param name="idToken">The ID token paired with <paramref name="accessToken"/>, or <c>null</c>.</param>
    /// <param name="expiresAt">Expiry of <paramref name="accessToken"/>, or <c>null</c> when unknown.</param>
    public static AccessTokenResult FromTicket(string? accessToken, string? refreshToken, string? idToken, DateTimeOffset? expiresAt) =>
        new() { AccessToken = accessToken, RefreshToken = refreshToken, IdToken = idToken, ExpiresAt = expiresAt };

    /// <summary>Creates the fail-closed result: the refresh token was rejected and the session has been signed out.</summary>
    public static AccessTokenResult SignedOut() => new() { SessionTerminated = true };
}
