using System.Globalization;

using b17s.Porta.Auth.Tokens;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace b17s.Porta.Auth.Providers;

/// <summary>
/// Builds an <see cref="AuthenticationContext"/> from the cookie auth ticket
/// populated by ASP.NET Core's OIDC handler. Tokens live on the ticket via
/// <c>SaveTokens = true</c>; refresh is delegated to <see cref="IAccessTokenRefreshService"/>.
/// </summary>
public sealed class SessionAuthProvider(
    IAccessTokenRefreshService accessTokenRefresh,
    ITokenRefreshService tokenRefreshService,
    IApiTokenService apiTokenService,
    ILogger<SessionAuthProvider> logger,
    TimeProvider? timeProvider = null) : IAuthenticationProvider
{
    private const string CookieScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <inheritdoc/>
    public async Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        var auth = await context.AuthenticateAsync(CookieScheme);
        if (!auth.Succeeded || auth.Principal is null || auth.Properties is null)
        {
            return AuthenticationContext.Unauthenticated();
        }

        // Refreshes if near expiry. The result is the up-to-date access token.
        var refreshResult = await accessTokenRefresh.GetAccessTokenAsync(context);
        if (refreshResult.SessionTerminated)
        {
            // The IdP rejected the refresh token (invalid_grant) and the refresh service signed
            // the session out. The per-request-cached auth ticket still holds the old access
            // token, so falling through to the ticket fallback below would resurrect the revoked
            // session for this request. Fail closed instead.
            return AuthenticationContext.Unauthenticated();
        }

        var accessToken = refreshResult.AccessToken;

        // Re-read after potential refresh - the ticket may now hold rotated tokens.
        if (accessToken is not null)
        {
            auth = await context.AuthenticateAsync(CookieScheme);
        }

        var properties = auth.Properties;
        var refreshToken = properties?.GetTokenValue("refresh_token");
        var idToken = properties?.GetTokenValue("id_token");
        var expiresAt = ParseExpiresAt(properties?.GetTokenValue("expires_at"));

        var authContext = new AuthenticationContext
        {
            AccessToken = accessToken ?? properties?.GetTokenValue("access_token"),
            RefreshToken = refreshToken,
            IdToken = idToken,
            ExpiresAt = expiresAt,
        };

        if (auth.Principal?.Identity?.IsAuthenticated == true)
        {
            // Group by type so multi-valued claims (e.g. multiple role claims) are all preserved
            // rather than collapsed to whichever happened to be enumerated last.
            foreach (var group in auth.Principal.Claims.GroupBy(c => c.Type))
            {
                authContext.Claims[group.Key] = group.Select(c => c.Value).ToArray();
            }
        }

        return authContext;
    }

    /// <inheritdoc/>
    public async Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(current.RefreshToken))
        {
            logger.RefreshFailed("no refresh token in context");
            return null;
        }

        try
        {
            var result = await tokenRefreshService.RefreshAsync(current.RefreshToken, cancellationToken);
            if (result.Response is null)
            {
                logger.RefreshFailed(result.IsInvalidGrant ? "invalid_grant (refresh token rejected)" : "service returned null");
                return null;
            }

            var response = result.Response;

            logger.SessionRefreshSucceeded(response.ExpiresIn);

            return new AuthenticationContext
            {
                AccessToken = response.AccessToken,
                RefreshToken = response.RefreshToken,
                IdToken = response.IdToken,
                ExpiresAt = _timeProvider.GetUtcNow().AddSeconds(response.ExpiresIn),
                Claims = new Dictionary<string, string[]>(current.Claims),
                Headers = new Dictionary<string, string>(current.Headers),
                ServiceTokens = new Dictionary<string, string>(current.ServiceTokens),
            };
        }
        catch (Exception ex)
        {
            logger.SessionRefreshError(ex);
            return null;
        }
    }

    /// <inheritdoc/>
    public async Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        await context.SignOutAsync(CookieScheme);
        await apiTokenService.InvalidateApiTokensAsync(context, cancellationToken);
    }

    private static DateTimeOffset? ParseExpiresAt(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)) return parsed;
        if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unixSeconds)) return DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        return null;
    }
}

internal static partial class SessionAuthProviderLogging
{
    [LoggerMessage(EventId = 13700, Level = LogLevel.Warning,
        Message = "Token refresh failed: {Reason}")]
    public static partial void RefreshFailed(this ILogger logger, string reason);

    [LoggerMessage(EventId = 13701, Level = LogLevel.Information,
        Message = "Session token refresh successful, expires in {ExpiresIn}s")]
    public static partial void SessionRefreshSucceeded(this ILogger logger, int expiresIn);

    [LoggerMessage(EventId = 13702, Level = LogLevel.Error,
        Message = "Session token refresh error")]
    public static partial void SessionRefreshError(this ILogger logger, Exception ex);
}
