using System.Security.Claims;

using b17s.Porta.Auth.Sessions;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Middleware;

/// <summary>
/// Middleware that provides session administration endpoints.
/// Admin-only: requires an authenticated caller satisfying the configured admin policy.
/// </summary>
/// <remarks>
/// Endpoints:
/// - GET {basePath}?email={email} - List sessions for a user
/// - DELETE {basePath}/{sessionId} - Terminate a specific session
/// - DELETE {basePath}?email={email} - Terminate all sessions for a user
///
/// Security: This middleware re-enforces the admin authorization policy in addition to
/// any outer pipeline check. There is no per-user "self" mode - every endpoint is
/// strictly admin-only, and every successful action is audit-logged with the admin's
/// identity and the target subject.
/// </remarks>
public sealed class SessionAdminMiddleware(
    RequestDelegate next,
    IOptions<SessionAdminOptions> options,
    ILogger<SessionAdminMiddleware> logger,
    string basePath = "/bff/admin/sessions")
{
    private readonly SessionAdminOptions _options = options.Value;
    private readonly string _basePath = basePath.TrimEnd('/');

    public async Task InvokeAsync(
        HttpContext context,
        ISessionManagementService sessionManagement)
    {
        var requestPath = context.Request.Path;

        if (!requestPath.StartsWithSegments(_basePath, StringComparison.OrdinalIgnoreCase, out var remaining))
        {
            await next(context);
            return;
        }

        using var activity = PortaActivitySource.Source.StartActivity("bff.session_admin");

        if (!await EnforceAdminAsync(context))
        {
            return;
        }

        var remainingPath = (remaining.Value ?? string.Empty).TrimStart('/');

        var method = context.Request.Method;

        if (method == "GET")
        {
            // GET /sessions?email={email} - List sessions for a user
            await HandleGetSessionsAsync(context, sessionManagement);
        }
        else if (method == "DELETE")
        {
            if (!await EnforceAntiforgeryAsync(context))
            {
                return;
            }

            if (string.IsNullOrEmpty(remainingPath))
            {
                // DELETE /sessions?email={email} - Terminate all sessions for a user
                await HandleTerminateByEmailAsync(context, sessionManagement);
            }
            else
            {
                // DELETE /sessions/{sessionId} - Terminate a specific session
                await HandleTerminateSessionAsync(context, sessionManagement, remainingPath);
            }
        }
        else
        {
            context.Response.StatusCode = 405;
            await context.Response.WriteAsJsonAsync(new { error = "Method not allowed" }, context.RequestAborted);
        }
    }

    private async Task<bool> EnforceAdminAsync(HttpContext context)
    {
        // Defense in depth: even if the outer pipeline branch was misconfigured,
        // this middleware refuses to act for unauthenticated or non-admin callers.
        if (context.User?.Identity?.IsAuthenticated != true)
        {
            logger.AdminUnauthenticated(context.Request.Path.Value ?? string.Empty);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "Authentication required" }, context.RequestAborted);
            return false;
        }

        var policyName = _options.RequirePolicy;
        if (string.IsNullOrEmpty(policyName))
        {
            // UseSessionAdmin enforces this at startup, but if the middleware is wired
            // up directly without a policy we fail closed rather than open.
            logger.AdminPolicyNotConfigured();
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new { error = "Access denied" }, context.RequestAborted);
            return false;
        }

        var authService = context.RequestServices.GetRequiredService<IAuthorizationService>();
        var result = await authService.AuthorizeAsync(context.User, policyName);
        if (!result.Succeeded)
        {
            logger.AdminAuthorizationFailed(GetCallerSubject(context.User), policyName);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new { error = "Access denied" }, context.RequestAborted);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Validates an antiforgery token on state-changing requests when the caller
    /// is authenticated via a cookie scheme. Token-auth callers (bearer /
    /// reference / API key) are exempt because their credentials are not
    /// auto-attached on cross-origin requests and so are not CSRF-vulnerable.
    /// Configured via <see cref="SessionAdminOptions.RequireAntiforgery"/>.
    /// </summary>
    private async Task<bool> EnforceAntiforgeryAsync(HttpContext context)
    {
        if (!_options.RequireAntiforgery)
        {
            return true;
        }

        if (!IsCookieAuthenticated(context.User))
        {
            return true;
        }

        var antiforgery = context.RequestServices.GetService<IAntiforgery>();
        if (antiforgery is null)
        {
            // Antiforgery wasn't registered (consumer didn't call AddAntiforgery).
            // Fail closed: a cookie-authenticated caller without an antiforgery
            // validator IS the CSRF vector this guard exists to close. Operators
            // who deliberately want no token (non-browser admin clients) opt
            // out via RequireAntiforgery = false.
            logger.AntiforgeryServiceMissing();
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "CSRF protection requires IAntiforgery to be registered. " +
                        "Call services.AddAntiforgery(), or set " +
                        "SessionAdminOptions.RequireAntiforgery = false for non-browser admin clients."
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
            logger.AntiforgeryValidationFailed(ex.Message);
            context.RequestServices.GetService<PortaMetrics>()?.RecordCsrfValidationFailure("session_admin");
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new { error = "Antiforgery validation failed" }, context.RequestAborted);
            return false;
        }
    }

    private static bool IsCookieAuthenticated(ClaimsPrincipal user)
    {
        if (user.Identity is null || !user.Identity.IsAuthenticated)
        {
            return false;
        }

        // A user may hold multiple identities (cookie + bearer transformed
        // identity, for example). Treat the caller as cookie-authenticated if
        // ANY identity was minted by a cookie scheme - that identity alone is
        // sufficient to make the request CSRF-attackable.
        foreach (var identity in user.Identities)
        {
            if (string.Equals(identity.AuthenticationType, CookieAuthenticationDefaults.AuthenticationScheme, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static string GetCallerSubject(ClaimsPrincipal user)
    {
        return user.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? user.FindFirstValue("sub")
            ?? user.FindFirstValue(ClaimTypes.Email)
            ?? user.FindFirstValue("email")
            ?? "unknown";
    }

    private async Task HandleGetSessionsAsync(HttpContext context, ISessionManagementService sessionManagement)
    {
        var email = context.Request.Query["email"].FirstOrDefault();

        if (string.IsNullOrEmpty(email))
        {
            logger.EmailParameterMissing();
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "email parameter is required" }, context.RequestAborted);
            return;
        }

        var admin = GetCallerSubject(context.User);
        logger.AdminListingSessionsForEmail(admin, email);
        var sessions = await sessionManagement.GetSessionsByEmailAsync(email, context.RequestAborted);

        await context.Response.WriteAsJsonAsync(new
        {
            email,
            sessionCount = sessions.Count,
            sessions = sessions.Select(s => new
            {
                sessionId = s.SessionId,
                userId = s.UserId,
                createdAt = s.CreatedAt,
                lastActivity = s.LastActivity,
                expiresAt = s.ExpiresAt,
                ipAddress = s.IpAddress,
                userAgent = s.UserAgent
            })
        }, context.RequestAborted);
    }

    private async Task HandleTerminateByEmailAsync(HttpContext context, ISessionManagementService sessionManagement)
    {
        var email = context.Request.Query["email"].FirstOrDefault();
        var revokeTokens = ParseRevokeTokens(context.Request.Query["revokeTokens"].FirstOrDefault());

        if (string.IsNullOrEmpty(email))
        {
            logger.EmailParameterMissing();
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "email parameter is required" }, context.RequestAborted);
            return;
        }

        var admin = GetCallerSubject(context.User);
        logger.AdminTerminatingSessionsByEmail(admin, email, revokeTokens);
        var terminatedCount = await sessionManagement.TerminateSessionsByEmailAsync(email, revokeTokens, context.RequestAborted, reason: "admin");

        logger.AdminSessionsTerminated(admin, terminatedCount, email);
        await context.Response.WriteAsJsonAsync(new
        {
            success = true,
            email,
            terminatedCount,
            tokensRevoked = revokeTokens
        }, context.RequestAborted);
    }

    private async Task HandleTerminateSessionAsync(HttpContext context, ISessionManagementService sessionManagement, string sessionId)
    {
        var revokeTokens = ParseRevokeTokens(context.Request.Query["revokeTokens"].FirstOrDefault());

        var admin = GetCallerSubject(context.User);
        var redactedSessionId = LogRedaction.RedactSessionId(sessionId);
        logger.AdminTerminatingSession(admin, redactedSessionId, revokeTokens);
        var success = await sessionManagement.TerminateSessionAsync(sessionId, revokeTokens, context.RequestAborted, reason: "admin");

        if (success)
        {
            logger.AdminSessionTerminated(admin, redactedSessionId);
            await context.Response.WriteAsJsonAsync(new
            {
                success = true,
                sessionId,
                tokensRevoked = revokeTokens
            }, context.RequestAborted);
        }
        else
        {
            logger.SessionNotFound(redactedSessionId);
            context.Response.StatusCode = 404;
            await context.Response.WriteAsJsonAsync(new { error = "Session not found" }, context.RequestAborted);
        }
    }

    /// <summary>
    /// Parses the <c>revokeTokens</c> query parameter. Default is <c>false</c> - an
    /// admin must explicitly pass <c>?revokeTokens=true</c> to trigger IdP-side
    /// revocation. The previous default-true semantics with a "anything other than
    /// the literal string 'false' enables revocation" parser was a surprising
    /// footgun on a destructive admin action.
    /// </summary>
    private static bool ParseRevokeTokens(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return false;

        return value.Equals("true", StringComparison.OrdinalIgnoreCase)
            || value.Equals("1", StringComparison.Ordinal)
            || value.Equals("yes", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// High-performance logging for SessionAdminMiddleware using compile-time source generators.
/// </summary>
internal static partial class SessionAdminMiddlewareLogging
{
    [LoggerMessage(
        EventId = 9800,
        Level = LogLevel.Warning,
        Message = "email parameter is missing from session admin request")]
    public static partial void EmailParameterMissing(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9801,
        Level = LogLevel.Information,
        Message = "Session admin audit: {Admin} listed sessions for {Email}")]
    public static partial void AdminListingSessionsForEmail(
        this ILogger logger,
        string admin,
        string email);

    [LoggerMessage(
        EventId = 9802,
        Level = LogLevel.Information,
        Message = "Session admin audit: {Admin} terminating all sessions for {Email}, revokeTokens: {RevokeTokens}")]
    public static partial void AdminTerminatingSessionsByEmail(
        this ILogger logger,
        string admin,
        string email,
        bool revokeTokens);

    [LoggerMessage(
        EventId = 9803,
        Level = LogLevel.Information,
        Message = "Session admin audit: {Admin} terminated {Count} sessions for {Email}")]
    public static partial void AdminSessionsTerminated(
        this ILogger logger,
        string admin,
        int count,
        string email);

    [LoggerMessage(
        EventId = 9804,
        Level = LogLevel.Information,
        Message = "Session admin audit: {Admin} terminating session {SessionId}, revokeTokens: {RevokeTokens}")]
    public static partial void AdminTerminatingSession(
        this ILogger logger,
        string admin,
        string sessionId,
        bool revokeTokens);

    [LoggerMessage(
        EventId = 9805,
        Level = LogLevel.Information,
        Message = "Session admin audit: {Admin} terminated session {SessionId}")]
    public static partial void AdminSessionTerminated(
        this ILogger logger,
        string admin,
        string sessionId);

    [LoggerMessage(
        EventId = 9806,
        Level = LogLevel.Warning,
        Message = "Session not found: {SessionId}")]
    public static partial void SessionNotFound(
        this ILogger logger,
        string sessionId);

    [LoggerMessage(
        EventId = 9807,
        Level = LogLevel.Warning,
        Message = "Session admin request rejected: unauthenticated caller for {Path}")]
    public static partial void AdminUnauthenticated(
        this ILogger logger,
        string path);

    [LoggerMessage(
        EventId = 9808,
        Level = LogLevel.Error,
        Message = "Session admin request rejected: no admin policy configured")]
    public static partial void AdminPolicyNotConfigured(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9809,
        Level = LogLevel.Warning,
        Message = "Session admin request rejected: caller {Admin} failed policy {Policy}")]
    public static partial void AdminAuthorizationFailed(
        this ILogger logger,
        string admin,
        string policy);

    [LoggerMessage(
        EventId = 9810,
        Level = LogLevel.Error,
        Message = "Session admin DELETE rejected: IAntiforgery is not registered and RequireAntiforgery=true")]
    public static partial void AntiforgeryServiceMissing(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9811,
        Level = LogLevel.Warning,
        Message = "Session admin DELETE rejected: antiforgery validation failed: {Reason}")]
    public static partial void AntiforgeryValidationFailed(
        this ILogger logger,
        string reason);
}
