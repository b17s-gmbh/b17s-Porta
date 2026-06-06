using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Middleware;

/// <summary>
/// Thin shim that triggers the framework OIDC handler's challenge flow.
/// State, nonce, PKCE, authorize-URL building, and the callback exchange are
/// all owned by <c>Microsoft.AspNetCore.Authentication.OpenIdConnect</c>.
/// </summary>
public sealed class OidcLoginMiddleware(
    RequestDelegate next,
    IOptions<OidcLoginOptions> options,
    IReturnUrlProtector returnUrlProtector,
    ILogger<OidcLoginMiddleware> logger,
    string path = "/bff/login")
{
    private readonly OidcLoginOptions _options = options.Value;
    private readonly string _path = path;
    private readonly string _signEndpointPath = path.TrimEnd('/') + "/sign-return-url";

    public async Task InvokeAsync(HttpContext context)
    {
        var requestPath = context.Request.Path.Value ?? string.Empty;

        if (requestPath.Equals(_signEndpointPath, StringComparison.OrdinalIgnoreCase))
        {
            await HandleSignReturnUrlAsync(context);
            return;
        }

        if (!requestPath.Equals(_path, StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        logger.LoginRequestReceived(context.Connection.RemoteIpAddress);

        var redirectUri = await ResolveRedirectUriAsync(context);
        if (redirectUri is null)
        {
            return;
        }

        var properties = new AuthenticationProperties { RedirectUri = redirectUri };
        await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, properties);
    }

    /// <summary>
    /// Resolves the post-login destination from the request, applying the open-
    /// redirect guard plus the signed-token policy. Returns the resolved URI on
    /// success, or <c>null</c> after writing a 400 response.
    /// </summary>
    private async Task<string?> ResolveRedirectUriAsync(HttpContext context)
    {
        // 1) Signed return_url token always wins. Issued by this server, so it
        //    is trusted without re-checking against the host allow-list.
        var signedToken = context.Request.Query["return_url"].FirstOrDefault();
        if (!string.IsNullOrEmpty(signedToken))
        {
            if (returnUrlProtector.TryUnprotect(signedToken, out var unwrapped))
            {
                return unwrapped;
            }

            logger.SignedReturnUrlInvalid();
            await WriteErrorAsync(context, 400, "Invalid or expired return_url");
            return null;
        }

        // 2) Raw redirect_uri is only honored under the looser policy: either the
        //    caller is already authenticated (so they could navigate there
        //    themselves), or the host has opted out of signed return URLs.
        var redirectUri = context.Request.Query["redirect_uri"].FirstOrDefault();
        if (string.IsNullOrEmpty(redirectUri))
        {
            return _options.DefaultRedirectUri;
        }

        var callerIsAuthenticated = context.User.Identity?.IsAuthenticated == true;
        if (_options.RequireSignedReturnUrl && !callerIsAuthenticated)
        {
            logger.UnsignedRedirectUriRejected(RedirectUriValidation.StripQueryForLogging(redirectUri));
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "redirect_uri must be signed",
                sign_endpoint = _signEndpointPath,
            }, context.RequestAborted);
            return null;
        }

        if (!IsValidRedirectUri(redirectUri, _options, context.Request))
        {
            logger.InvalidRedirectUriRejected(RedirectUriValidation.StripQueryForLogging(redirectUri));
            await WriteErrorAsync(context, 400, "Invalid redirect URI");
            return null;
        }

        return redirectUri;
    }

    private static async Task WriteErrorAsync(HttpContext context, int statusCode, string error)
    {
        context.Response.StatusCode = statusCode;
        await context.Response.WriteAsJsonAsync(new { error }, context.RequestAborted);
    }

    /// <summary>
    /// Helper endpoint for trusted callers: exchanges a redirect URI for a
    /// signed, time-limited token suitable for use as <c>return_url</c> on the
    /// login endpoint. Only available to authenticated callers.
    /// </summary>
    private async Task HandleSignReturnUrlAsync(HttpContext context)
    {
        // CSRF defense: this endpoint mints a token bound to the current session
        // (the authenticated caller's identity). Require POST so that
        // SameSite=Lax cookies do not attach on a cross-origin top-level GET or
        // image-tag fetch, and so the request is not safely cacheable.
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            logger.SignReturnUrlMethodNotAllowed(context.Request.Method);
            context.Response.StatusCode = 405;
            context.Response.Headers.Allow = "POST";
            await context.Response.WriteAsJsonAsync(new { error = "Method not allowed" }, context.RequestAborted);
            return;
        }

        if (context.User.Identity?.IsAuthenticated != true)
        {
            await WriteErrorAsync(context, 401, "Authentication required");
            return;
        }

        var redirectUri = context.Request.Query["redirect_uri"].FirstOrDefault();
        if (string.IsNullOrEmpty(redirectUri) || !IsValidRedirectUri(redirectUri, _options, context.Request))
        {
            await WriteErrorAsync(context, 400, "Invalid redirect URI");
            return;
        }

        var token = returnUrlProtector.Protect(redirectUri, _options.ReturnUrlTtl);
        await context.Response.WriteAsJsonAsync(new
        {
            return_url = token,
            expires_in = (int)_options.ReturnUrlTtl.TotalSeconds,
        }, context.RequestAborted);
    }

    private bool IsValidRedirectUri(string uri, OidcLoginOptions options, HttpRequest request)
    {
        if (string.IsNullOrEmpty(uri))
            return false;

        // Allow only safe relative URIs (same-origin) - reject protocol-relative
        // (`//host`) and backslash variants (`/\host`) which resolve to external origins.
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

        // Same-origin: host (IDN-normalized) AND port must match the request's host.
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

internal static partial class OidcLoginLog
{
    [LoggerMessage(EventId = 9500, Level = LogLevel.Information,
        Message = "Login request received from {RemoteIp}")]
    public static partial void LoginRequestReceived(this ILogger<OidcLoginMiddleware> logger, System.Net.IPAddress? remoteIp);

    [LoggerMessage(EventId = 9501, Level = LogLevel.Warning,
        Message = "Invalid redirect URI rejected: {RedirectUri}")]
    public static partial void InvalidRedirectUriRejected(this ILogger<OidcLoginMiddleware> logger, string redirectUri);

    [LoggerMessage(EventId = 9502, Level = LogLevel.Warning,
        Message = "Redirect URI rejected - not HTTPS: {Uri}")]
    public static partial void RedirectUriNotHttps(this ILogger<OidcLoginMiddleware> logger, string uri);

    [LoggerMessage(EventId = 9503, Level = LogLevel.Warning,
        Message = "Redirect URI rejected - host not in whitelist: {Host}")]
    public static partial void RedirectUriHostNotWhitelisted(this ILogger<OidcLoginMiddleware> logger, string host);

    [LoggerMessage(EventId = 9504, Level = LogLevel.Warning,
        Message = "Signed return_url token failed verification (forged, tampered, or expired)")]
    public static partial void SignedReturnUrlInvalid(this ILogger<OidcLoginMiddleware> logger);

    [LoggerMessage(EventId = 9505, Level = LogLevel.Warning,
        Message = "Unsigned redirect_uri from unauthenticated caller rejected (RequireSignedReturnUrl=true): {RedirectUri}")]
    public static partial void UnsignedRedirectUriRejected(this ILogger<OidcLoginMiddleware> logger, string redirectUri);

    [LoggerMessage(EventId = 9506, Level = LogLevel.Warning,
        Message = "sign-return-url request rejected - method {Method} not allowed (POST required)")]
    public static partial void SignReturnUrlMethodNotAllowed(this ILogger<OidcLoginMiddleware> logger, string method);
}
