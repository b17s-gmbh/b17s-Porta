using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Middleware;

/// <summary>
/// Thin shim that triggers the framework OIDC handler's sign-out flow.
/// End-session URL building, post-logout redirect, and id_token_hint are owned
/// by <c>Microsoft.AspNetCore.Authentication.OpenIdConnect</c>.
///
/// The shim adds two BFF-specific behaviors:
/// <list type="bullet">
///   <item>Open-redirect guard on the <c>redirect_uri</c> query parameter.</item>
///   <item>Optional RFC 7009 token revocation against the IdP using the refresh
///     token from the cookie auth ticket. The framework does not do this.</item>
/// </list>
/// </summary>
public sealed class OidcLogoutMiddleware(
    RequestDelegate next,
    IOptions<OidcLogoutOptions> options,
    ILogger<OidcLogoutMiddleware> logger,
    string path = "/bff/logout")
{
    private readonly OidcLogoutOptions _options = options.Value;
    private readonly string _path = path;

    /// <summary>
    /// Handles a logout request at the configured path; other requests pass through. Requires POST
    /// (and optional antiforgery) for CSRF protection, optionally revokes the refresh token against
    /// the IdP (RFC 7009), tears down the server-side Porta session, and signs the caller out of the
    /// cookie and (for global logout) OIDC schemes, returning JSON or a redirect per configuration.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="tokenRevocationService">Service used to revoke the refresh token at the IdP when global logout is enabled.</param>
    /// <returns>A task that completes when the request has been handled or passed to the next middleware.</returns>
    public async Task InvokeAsync(HttpContext context, ITokenRevocationService tokenRevocationService)
    {
        var requestPath = context.Request.Path.Value ?? string.Empty;
        if (!requestPath.Equals(_path, StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        // CSRF defense: logout is a state-changing operation (cookie + IdP revocation),
        // so it must not be reachable via `<img src=…>`, top-level GET navigation, or
        // any other request that a SameSite=Lax cookie attaches to. Require POST.
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            logger.LogoutMethodNotAllowed(context.Request.Method);
            context.Response.StatusCode = 405;
            context.Response.Headers.Allow = "POST";
            await context.Response.WriteAsJsonAsync(new { error = "Method not allowed" }, context.RequestAborted);
            return;
        }

        if (!await EnforceAntiforgeryAsync(context))
        {
            return;
        }

        logger.LogoutRequestReceived(context.Connection.RemoteIpAddress);

        var auth = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!auth.Succeeded)
        {
            logger.LogoutAttemptedByUnauthenticatedUser();
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { error = "Not authenticated" }, context.RequestAborted);
            return;
        }

        var redirectUri = context.Request.Query["redirect_uri"].FirstOrDefault();
        if (!string.IsNullOrEmpty(redirectUri) && !IsValidRedirectUri(redirectUri, _options, context.Request))
        {
            logger.InvalidRedirectUriRejected(RedirectUriValidation.StripQueryForLogging(redirectUri));
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "Invalid redirect URI" }, context.RequestAborted);
            return;
        }

        redirectUri ??= _options.DefaultRedirectUri;

        bool tokensRevoked = false;
        if (_options.PerformGlobalLogout)
        {
            tokensRevoked = await TryRevokeTokensAsync(auth, tokenRevocationService, context.RequestAborted);
        }

        // Tear down the server-side Porta session metadata for this login and record the
        // invalidation (decrementing bff.sessions.active). The cookie/OIDC sign-out below clears the
        // auth ticket + client cookie, but not the Porta metadata/admin indexes - terminating here
        // keeps the active-sessions gauge balanced against RegisterSessionAsync and removes the
        // now-defunct session from admin "who's logged in" queries.
        await TerminateServerSessionAsync(context, auth);

        if (_options.ReturnJson)
        {
            // SPA-style: tear down the cookie and return JSON for the client to
            // navigate. We don't trigger SignOutAsync against OIDC because that
            // issues a 302 to the IdP end-session endpoint - incompatible with
            // ReturnJson semantics.
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            context.Response.StatusCode = 200;
            await context.Response.WriteAsJsonAsync(new
            {
                success = true,
                logoutType = _options.PerformGlobalLogout ? "global" : "local",
                redirectUrl = redirectUri,
                localSessionCleared = true,
                tokensRevoked,
            }, context.RequestAborted);
            logger.LogoutCompleted(_options.PerformGlobalLogout ? "global" : "local", true, tokensRevoked);
            return;
        }

        // Browser flow: framework signs out the cookie scheme + (for global)
        // redirects to the IdP's end-session endpoint via the OIDC handler.
        var properties = new AuthenticationProperties { RedirectUri = redirectUri };

        if (_options.PerformGlobalLogout)
        {
            logger.PerformingGlobalLogout();
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, properties);
        }
        else
        {
            logger.PerformingLocalLogout();
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme, properties);
            // Local-only: framework won't redirect, do it manually.
            if (!context.Response.HasStarted)
            {
                context.Response.Redirect(redirectUri);
            }
        }

        logger.LogoutCompleted(_options.PerformGlobalLogout ? "global" : "local", true, tokensRevoked);
    }

    // Defense-in-depth on top of the POST-only gate. The HTTP-method check
    // closes the SameSite=Lax CSRF vector for top-level GETs, but if an
    // operator later flips the auth cookie to SameSite=None (cross-site
    // embedded scenarios), a cross-origin POST would attach the cookie and
    // trigger logout + IdP-side revocation as a side effect. Antiforgery
    // closes that. Configured via OidcLogoutOptions.RequireAntiforgery.
    private async Task<bool> EnforceAntiforgeryAsync(HttpContext context)
    {
        if (!_options.RequireAntiforgery)
        {
            return true;
        }

        var antiforgery = context.RequestServices.GetService<IAntiforgery>();
        if (antiforgery is null)
        {
            // Fail closed: the consumer asked for antiforgery but didn't
            // register IAntiforgery. Operators with non-browser logout
            // callers opt out via RequireAntiforgery = false.
            logger.LogoutAntiforgeryServiceMissing();
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "CSRF protection requires IAntiforgery to be registered. " +
                        "Call services.AddAntiforgery(), or set " +
                        "OidcLogoutOptions.RequireAntiforgery = false for non-browser logout clients."
            }, context.RequestAborted);
            return false;
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context);
            return true;
        }
        catch (AntiforgeryValidationException ex)
        {
            logger.LogoutAntiforgeryValidationFailed(ex.Message);
            context.RequestServices.GetService<PortaMetrics>()?.RecordCsrfValidationFailure("oidc_logout");
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new { error = "Antiforgery validation failed" }, context.RequestAborted);
            return false;
        }
    }

    // Mirror of the session-id key written onto the cookie ticket at sign-in
    // (AuthenticationServiceExtensions.OnTokenValidated). Used to terminate the matching Porta
    // session metadata on logout. Kept private/local, consistent with the other call sites.
    private const string SessionIdPropertyKey = ".bff.session_id";

    private static async Task TerminateServerSessionAsync(HttpContext context, AuthenticateResult auth)
    {
        var sessionManagement = context.RequestServices.GetService<ISessionManagementService>();
        if (sessionManagement is null)
        {
            // Session management isn't wired (e.g. cookie-only setups without admin/back-channel
            // logout). Nothing server-side to tear down; the cookie sign-out below still applies.
            return;
        }

        if (auth.Properties?.Items.TryGetValue(SessionIdPropertyKey, out var sessionId) == true
            && !string.IsNullOrEmpty(sessionId))
        {
            // revokeTokens: false - this middleware already performed RFC 7009 revocation above when
            // PerformGlobalLogout is set, so we must not trigger a second revoke round-trip here.
            await sessionManagement.TerminateSessionAsync(sessionId, revokeTokens: false, context.RequestAborted, reason: "logout");
        }
    }

    private async Task<bool> TryRevokeTokensAsync(AuthenticateResult auth, ITokenRevocationService tokenRevocationService, CancellationToken cancellationToken)
    {
        var refreshToken = auth.Properties?.GetTokenValue("refresh_token");
        if (string.IsNullOrEmpty(refreshToken))
        {
            return false;
        }

        try
        {
            // RFC 7009: revoking the refresh token cascades to access tokens for
            // most IdPs, so we don't need to revoke the access token separately.
            return await tokenRevocationService.RevokeTokenAsync(refreshToken, "refresh_token", cancellationToken);
        }
        catch (Exception ex)
        {
            logger.TokenRevocationError(ex);
            return false;
        }
    }

    private bool IsValidRedirectUri(string uri, OidcLogoutOptions options, HttpRequest request)
    {
        if (string.IsNullOrEmpty(uri))
            return false;

        if (uri.StartsWith('/'))
            return RedirectUriValidation.IsSafeRelativeUri(uri);

        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri))
            return false;

        var isLoopback = RedirectUriValidation.IsLocalhost(parsedUri.Host);
        if (parsedUri.Scheme != "https" && !isLoopback)
        {
            logger.RedirectUriNotHttps(RedirectUriValidation.StripQueryForLogging(uri));
            return false;
        }

        var requestHostNormalized = RedirectUriValidation.NormalizeHost(request.Host.Host);
        var redirectHostNormalized = RedirectUriValidation.NormalizeHost(parsedUri.Host);
        var redirectPort = parsedUri.IsDefaultPort ? -1 : parsedUri.Port;
        var requestPort = request.Host.Port ?? -1;
        if (string.Equals(requestHostNormalized, redirectHostNormalized, StringComparison.Ordinal)
            && requestPort == redirectPort)
        {
            return true;
        }

        if (options.AllowedRedirectHosts.Count > 0)
        {
            var isAllowed = RedirectUriValidation.MatchesAllowedHost(parsedUri, options.AllowedRedirectHosts);
            if (!isAllowed)
            {
                logger.RedirectUriHostNotWhitelisted(parsedUri.Host);
            }
            return isAllowed;
        }

        return options.AllowLocalhost && isLoopback;
    }
}

internal static partial class OidcLogoutLog
{
    [LoggerMessage(EventId = 9600, Level = LogLevel.Information,
        Message = "Logout request received from {RemoteIp}")]
    public static partial void LogoutRequestReceived(this ILogger<OidcLogoutMiddleware> logger, System.Net.IPAddress? remoteIp);

    [LoggerMessage(EventId = 9601, Level = LogLevel.Warning,
        Message = "Logout attempted by unauthenticated user")]
    public static partial void LogoutAttemptedByUnauthenticatedUser(this ILogger<OidcLogoutMiddleware> logger);

    [LoggerMessage(EventId = 9602, Level = LogLevel.Warning,
        Message = "Invalid redirect URI rejected: {RedirectUri}")]
    public static partial void InvalidRedirectUriRejected(this ILogger<OidcLogoutMiddleware> logger, string redirectUri);

    [LoggerMessage(EventId = 9603, Level = LogLevel.Warning,
        Message = "Redirect URI rejected - not HTTPS: {Uri}")]
    public static partial void RedirectUriNotHttps(this ILogger<OidcLogoutMiddleware> logger, string uri);

    [LoggerMessage(EventId = 9604, Level = LogLevel.Warning,
        Message = "Redirect URI rejected - host not in whitelist: {Host}")]
    public static partial void RedirectUriHostNotWhitelisted(this ILogger<OidcLogoutMiddleware> logger, string host);

    [LoggerMessage(EventId = 9605, Level = LogLevel.Debug,
        Message = "Performing global logout (session + IdP)")]
    public static partial void PerformingGlobalLogout(this ILogger<OidcLogoutMiddleware> logger);

    [LoggerMessage(EventId = 9606, Level = LogLevel.Debug,
        Message = "Performing local logout (session only)")]
    public static partial void PerformingLocalLogout(this ILogger<OidcLogoutMiddleware> logger);

    [LoggerMessage(EventId = 9607, Level = LogLevel.Debug,
        Message = "{LogoutType} logout completed: SessionCleared={SessionCleared}, TokensRevoked={TokensRevoked}")]
    public static partial void LogoutCompleted(this ILogger<OidcLogoutMiddleware> logger, string logoutType, bool sessionCleared, bool tokensRevoked);

    [LoggerMessage(EventId = 9608, Level = LogLevel.Warning,
        Message = "Token revocation failed during logout")]
    public static partial void TokenRevocationError(this ILogger<OidcLogoutMiddleware> logger, Exception ex);

    [LoggerMessage(EventId = 9609, Level = LogLevel.Warning,
        Message = "Logout request rejected - method {Method} not allowed (POST required)")]
    public static partial void LogoutMethodNotAllowed(this ILogger<OidcLogoutMiddleware> logger, string method);

    [LoggerMessage(EventId = 9610, Level = LogLevel.Error,
        Message = "Logout POST rejected: IAntiforgery is not registered and RequireAntiforgery=true")]
    public static partial void LogoutAntiforgeryServiceMissing(this ILogger<OidcLogoutMiddleware> logger);

    [LoggerMessage(EventId = 9611, Level = LogLevel.Warning,
        Message = "Logout POST rejected: antiforgery validation failed: {Reason}")]
    public static partial void LogoutAntiforgeryValidationFailed(this ILogger<OidcLogoutMiddleware> logger, string reason);
}
