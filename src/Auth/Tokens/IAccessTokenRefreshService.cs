using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Returns a current access token for the authenticated user, refreshing it
/// transparently if it is near expiry. The framework's OIDC handler stores
/// tokens on the cookie ticket via <c>SaveTokens = true</c>; this service
/// reads them, refreshes when needed, and writes the rotated tokens back so
/// that subsequent reads see the fresh values.
/// </summary>
public interface IAccessTokenRefreshService
{
    /// <summary>
    /// Returns the current access token for the request, refreshing if near expiry.
    /// The result carries no token (<see cref="AccessTokenResult.None"/>) when the request is
    /// unauthenticated or no access token is present. When the IdP rejects the refresh token
    /// (<c>invalid_grant</c>), the session is signed out and the result reports
    /// <see cref="AccessTokenResult.SessionTerminated"/> — callers must then treat the request
    /// as unauthenticated rather than fall back to the ticket's stale access token.
    /// </summary>
    Task<AccessTokenResult> GetAccessTokenAsync(HttpContext context);

    /// <summary>
    /// Forces an access-token refresh regardless of expiry and writes the rotated tokens back
    /// to the cookie ticket. Used by the backend caller's opt-in refresh-on-401 path: a backend
    /// rejected the current token, so proactive expiry checks don't apply.
    /// <para>
    /// Runs under the same per-user lock as <see cref="GetAccessTokenAsync"/>. When
    /// <paramref name="staleAccessToken"/> is supplied and another request has already rotated the
    /// token under the lock, the already-rotated token is returned without a second IdP round-trip.
    /// Returns the current (or rotated) token on failure rather than null, so the caller can decide
    /// whether the retry is worthwhile; returns null only when the request is unauthenticated.
    /// </para>
    /// </summary>
    /// <param name="context">The current request context.</param>
    /// <param name="staleAccessToken">The token the backend rejected, used to detect a concurrent refresh.</param>
    Task<string?> ForceRefreshAsync(HttpContext context, string? staleAccessToken = null);
}
