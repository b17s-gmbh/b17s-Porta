using System.Text.Json;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace b17s.Porta.Middleware;

/// <summary>
/// Middleware that handles OIDC back-channel logout requests from the IdP.
/// This enables "logout from one app = logout from all apps" functionality.
/// </summary>
/// <remarks>
/// Back-channel logout is an IdP-initiated logout flow where the IdP sends a signed
/// logout_token JWT directly to the BFF's logout endpoint. The BFF validates the token
/// and terminates the matching session.
///
/// This is the one exception to the "no JWT validation" rule, as back-channel logout
/// requires validating the logout_token signature to prevent malicious logout requests.
/// </remarks>
public sealed class OidcBackChannelLogoutMiddleware(
    RequestDelegate next,
    IOptions<OidcBackChannelLogoutOptions> options,
    ILogger<OidcBackChannelLogoutMiddleware> logger,
    string path = "/bff/backchannel-logout",
    TimeProvider? timeProvider = null)
{
    private const string BackChannelLogoutEventType = "http://schemas.openid.net/event/backchannel-logout";
    private const string JtiReplayCacheKeyPrefix = "porta:bcl:jti:";
    private readonly OidcBackChannelLogoutOptions _options = options.Value;
    private readonly string _path = path;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Handles an IdP-initiated back-channel logout request. Requests to other paths pass through.
    /// At the configured path the middleware validates the posted <c>logout_token</c> JWT (content
    /// type, size, signature, <c>typ</c>, <c>events</c>, and <c>jti</c> replay protection), then
    /// terminates the matching session(s) by <c>sid</c> or, failing that, by <c>sub</c>.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="discoveryService">Resolves the IdP signing keys used to validate the logout token.</param>
    /// <param name="sessionManagement">Terminates the sessions identified by the logout token.</param>
    /// <param name="configOptions">Session authentication configuration (authority, client id) used during validation.</param>
    /// <param name="replayCache">Distributed cache tracking consumed <c>jti</c> values for replay protection.</param>
    /// <returns>A task that completes when the request has been handled.</returns>
    public async Task InvokeAsync(
        HttpContext context,
        IDiscoveryService discoveryService,
        ISessionManagementService sessionManagement,
        IOptions<SessionAuthenticationConfiguration> configOptions,
        IDistributedCache replayCache)
    {
        var config = configOptions.Value;
        var path = context.Request.Path.Value ?? string.Empty;

        if (!path.Equals(_path, StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        // Back-channel logout must be POST
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            logger.InvalidHttpMethod(context.Request.Method);
            context.Response.StatusCode = 405;
            return;
        }

        var options = _options;

        // Spec requires application/x-www-form-urlencoded. Reject other content
        // types before touching the body - this endpoint is anonymous, so any
        // body work an attacker can force on us must be bounded.
        var contentType = context.Request.ContentType ?? string.Empty;
        if (!contentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            logger.InvalidContentType(contentType);
            context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
            return;
        }

        // Require a known, bounded Content-Length. This blocks chunked uploads
        // with no length declared and caps body size on an anonymous endpoint.
        var contentLength = context.Request.ContentLength;
        if (contentLength is null || contentLength <= 0)
        {
            logger.MissingContentLength();
            context.Response.StatusCode = StatusCodes.Status411LengthRequired;
            return;
        }
        if (contentLength > options.MaxRequestBodyBytes)
        {
            logger.RequestBodyTooLarge(contentLength.Value, options.MaxRequestBodyBytes);
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }

        using var activity = PortaActivitySource.Source.StartActivity("bff.backchannel_logout");
        logger.BackChannelLogoutReceived(context.Connection.RemoteIpAddress);

        // Read the logout_token from the form body with tight limits. The spec
        // only defines a single `logout_token` field carrying a JWT.
        // FormOptions in .NET 10 has no per-form key count limit; ValueCountLimit
        // bounds the total number of entries. The spec only defines `logout_token`,
        // so 4 is generous. Cap key/value lengths and the (unused but-applies-to-
        // multipart) body length too, in case a client sends multipart by mistake.
        var formOptions = new FormOptions
        {
            BufferBody = false,
            KeyLengthLimit = 64,
            ValueLengthLimit = (int)Math.Min(options.MaxRequestBodyBytes, int.MaxValue),
            ValueCountLimit = 4,
            MultipartBodyLengthLimit = options.MaxRequestBodyBytes,
        };
        var form = await context.Request.ReadFormAsync(formOptions, context.RequestAborted);
        var logoutToken = form["logout_token"].FirstOrDefault();

        if (string.IsNullOrEmpty(logoutToken))
        {
            logger.LogoutTokenMissing();
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "logout_token is required" }, context.RequestAborted);
            return;
        }

        if (logoutToken.Length > options.MaxLogoutTokenLength)
        {
            logger.LogoutTokenTooLong(logoutToken.Length, options.MaxLogoutTokenLength);
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }

        try
        {
            // Validate the logout token
            var validatedToken = await ValidateLogoutTokenAsync(logoutToken, discoveryService, config, options, context.RequestAborted);

            if (validatedToken == null)
            {
                logger.LogoutTokenValidationFailed("Token validation returned null");
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "Invalid logout_token" }, context.RequestAborted);
                return;
            }

            // Extract session ID (sid) claim
            var sessionId = validatedToken.Claims.FirstOrDefault(c => c.Type == "sid")?.Value;
            var subject = validatedToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            if (string.IsNullOrEmpty(sessionId) && string.IsNullOrEmpty(subject))
            {
                logger.LogoutTokenMissingSidAndSub();
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "logout_token must contain sid or sub claim" }, context.RequestAborted);
                return;
            }

            // Replay protection: per OIDC back-channel logout spec, RPs SHOULD reject
            // logout_tokens whose jti has been seen within the token's lifetime.
            // We require a jti to be present so that we can enforce this.
            var jti = validatedToken.Claims.FirstOrDefault(c => c.Type == "jti")?.Value;
            if (string.IsNullOrEmpty(jti))
            {
                logger.LogoutTokenMissingJti();
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "logout_token must contain jti claim" }, context.RequestAborted);
                return;
            }

            var replayKey = JtiReplayCacheKeyPrefix + jti;
            if (await replayCache.GetAsync(replayKey, context.RequestAborted) is not null)
            {
                logger.LogoutTokenReplayDetected(jti);
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "logout_token replay detected" }, context.RequestAborted);
                return;
            }

            // Mark the jti as consumed for the remaining lifetime of the token plus
            // the configured clock skew, so a token cannot be replayed within its
            // accepted-validity window even on a different node. Clamp the TTL: a
            // misconfigured IdP could mint a token with a far-future `exp` (a missing
            // `exp` is already rejected by lifetime validation), which would otherwise
            // pin the jti in cache for that long.
            var ttl = (validatedToken.ValidTo - _timeProvider.GetUtcNow().UtcDateTime) + options.ClockSkew;
            if (ttl > options.MaxReplayCacheTtl)
            {
                ttl = options.MaxReplayCacheTtl;
            }
            if (ttl > TimeSpan.Zero)
            {
                await replayCache.SetAsync(
                    replayKey,
                    [1],
                    new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl },
                    context.RequestAborted);
            }

            // Terminate the session
            var terminatedCount = 0;
            if (!string.IsNullOrEmpty(sessionId))
            {
                logger.TerminatingSessionById(LogRedaction.RedactSessionId(sessionId));
                var success = await sessionManagement.TerminateSessionAsync(sessionId, revokeTokens: false, context.RequestAborted, reason: "backchannel");
                terminatedCount = success ? 1 : 0;
            }
            else if (!string.IsNullOrEmpty(subject))
            {
                // If only sub is provided, look up sessions via the subject (sub) index.
                // The OIDC `sub` claim is an opaque IdP-scoped identifier (typically a UUID)
                // and must not be looked up via the email index - doing so would silently
                // fail to terminate sessions in the common case (sub != email), bypassing
                // the IdP-initiated logout security control.
                logger.TerminatingSessionsBySubject(subject, LogRedaction.FingerprintSubject(subject));
                terminatedCount = await sessionManagement.TerminateSessionsBySubjectAsync(subject, revokeTokens: false, context.RequestAborted, reason: "backchannel");
            }

            logger.BackChannelLogoutCompleted(terminatedCount);
            activity?.SetTag("sessions_terminated", terminatedCount);

            // OIDC spec: return 200 OK for successful logout
            context.Response.StatusCode = 200;
        }
        catch (SecurityTokenValidationException ex)
        {
            logger.LogoutTokenValidationFailed(ex.Message);
            activity?.SetStatus(System.Diagnostics.ActivityStatusCode.Error, ex.Message);
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(new { error = "Invalid logout_token" }, context.RequestAborted);
        }
        catch (Exception ex)
        {
            logger.BackChannelLogoutError(ex);
            activity?.SetStatus(System.Diagnostics.ActivityStatusCode.Error, ex.Message);
            context.Response.StatusCode = 500;
        }
    }

    private async Task<JsonWebToken?> ValidateLogoutTokenAsync(
        string logoutToken,
        IDiscoveryService discoveryService,
        SessionAuthenticationConfiguration config,
        OidcBackChannelLogoutOptions options,
        CancellationToken cancellationToken)
    {
        var validationParameters = new JwtValidationParameters
        {
            Authority = config.Authority,
            Audience = config.ClientId,
            ValidateIssuer = options.ValidateIssuer,
            ValidateAudience = options.ValidateAudience,
            ValidateSignature = options.ValidateSignature,
            ValidateLifetime = true,
            ClockSkew = options.ClockSkew,
            // Logout tokens don't carry a nonce.
        };

        var result = await JwtValidationHelper.ValidateAsync(logoutToken, discoveryService, validationParameters, logger, cancellationToken);

        switch (result.Reason)
        {
            case JwtValidationFailureReason.None:
                break;
            case JwtValidationFailureReason.AuthorityNotConfigured:
                logger.AuthorityNotConfigured();
                return null;
            case JwtValidationFailureReason.DiscoveryFailed:
                logger.DiscoveryFailed(config.Authority);
                return null;
            case JwtValidationFailureReason.NotJwt:
                logger.LogoutTokenNotJwt();
                return null;
            default:
                logger.LogoutTokenValidationFailed(result.ErrorMessage ?? result.Reason.ToString());
                return null;
        }

        var jwtToken = result.Token!;

        // OIDC back-channel logout spec §2.4: JWT header `typ` MUST be `logout+jwt`.
        // This is the primary defense against an attacker presenting a signed
        // id_token or access_token from the same issuer/audience as a "logout"
        // (those tokens already pass signature, issuer, and audience checks).
        // The `events` claim check below is defense-in-depth; without `typ`
        // enforcement, any signed JWT whose `events` is forgeable would qualify.
        if (options.RequireLogoutTypHeader)
        {
            var typ = jwtToken.Typ;
            if (!string.Equals(typ, "logout+jwt", StringComparison.Ordinal))
            {
                logger.LogoutTokenInvalidTyp(string.IsNullOrEmpty(typ) ? "(missing)" : typ);
                return null;
            }
        }

        // OIDC back-channel logout spec (§2.4): a logout_token MUST NOT contain a
        // nonce claim. Presence of nonce indicates the IdP confused this with an
        // id_token flow - reject to keep the contract tight.
        if (jwtToken.Claims.Any(c => c.Type == "nonce"))
        {
            logger.LogoutTokenContainsNonce();
            return null;
        }

        var eventsClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "events")?.Value;
        if (string.IsNullOrEmpty(eventsClaim))
        {
            logger.LogoutTokenMissingEventsClaim();
            return null;
        }

        try
        {
            var eventsJson = JsonDocument.Parse(eventsClaim);
            if (!eventsJson.RootElement.TryGetProperty(BackChannelLogoutEventType, out _))
            {
                logger.LogoutTokenInvalidEventType(eventsClaim);
                return null;
            }
        }
        catch (JsonException)
        {
            logger.LogoutTokenInvalidEventsFormat(eventsClaim);
            return null;
        }

        return jwtToken;
    }
}

/// <summary>
/// High-performance logging for OidcBackChannelLogoutMiddleware using compile-time source generators.
/// </summary>
internal static partial class OidcBackChannelLogoutMiddlewareLogging
{
    [LoggerMessage(
        EventId = 9700,
        Level = LogLevel.Information,
        Message = "Back-channel logout request received from {RemoteIp}")]
    public static partial void BackChannelLogoutReceived(
        this ILogger logger,
        System.Net.IPAddress? remoteIp);

    [LoggerMessage(
        EventId = 9701,
        Level = LogLevel.Warning,
        Message = "Invalid HTTP method for back-channel logout: {Method}")]
    public static partial void InvalidHttpMethod(
        this ILogger logger,
        string method);

    [LoggerMessage(
        EventId = 9702,
        Level = LogLevel.Warning,
        Message = "logout_token is missing from back-channel logout request")]
    public static partial void LogoutTokenMissing(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9703,
        Level = LogLevel.Warning,
        Message = "logout_token validation failed: {Reason}")]
    public static partial void LogoutTokenValidationFailed(
        this ILogger logger,
        string reason);

    [LoggerMessage(
        EventId = 9704,
        Level = LogLevel.Warning,
        Message = "logout_token must contain sid or sub claim")]
    public static partial void LogoutTokenMissingSidAndSub(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9705,
        Level = LogLevel.Debug,
        Message = "Terminating session by ID: {SessionId}")]
    public static partial void TerminatingSessionById(
        this ILogger logger,
        string sessionId);

    [LoggerMessage(
        EventId = 9706,
        Level = LogLevel.Debug,
        Message = "Terminating sessions by subject: {Subject} ({SubjectHash})")]
    public static partial void TerminatingSessionsBySubject(
        this ILogger logger,
        string subject,
        string subjectHash);

    [LoggerMessage(
        EventId = 9707,
        Level = LogLevel.Information,
        Message = "Back-channel logout completed: {TerminatedCount} sessions terminated")]
    public static partial void BackChannelLogoutCompleted(
        this ILogger logger,
        int terminatedCount);

    [LoggerMessage(
        EventId = 9708,
        Level = LogLevel.Error,
        Message = "Back-channel logout error")]
    public static partial void BackChannelLogoutError(
        this ILogger logger,
        Exception ex);

    [LoggerMessage(
        EventId = 9709,
        Level = LogLevel.Warning,
        Message = "Authority not configured for back-channel logout")]
    public static partial void AuthorityNotConfigured(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9710,
        Level = LogLevel.Warning,
        Message = "Discovery failed for authority: {Authority}")]
    public static partial void DiscoveryFailed(
        this ILogger logger,
        string authority);

    [LoggerMessage(
        EventId = 9711,
        Level = LogLevel.Warning,
        Message = "logout_token is not a valid JWT")]
    public static partial void LogoutTokenNotJwt(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9712,
        Level = LogLevel.Warning,
        Message = "logout_token missing 'events' claim")]
    public static partial void LogoutTokenMissingEventsClaim(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9713,
        Level = LogLevel.Warning,
        Message = "logout_token has invalid event type: {Events}")]
    public static partial void LogoutTokenInvalidEventType(
        this ILogger logger,
        string events);

    [LoggerMessage(
        EventId = 9714,
        Level = LogLevel.Warning,
        Message = "logout_token has invalid 'events' format: {Events}")]
    public static partial void LogoutTokenInvalidEventsFormat(
        this ILogger logger,
        string events);

    [LoggerMessage(
        EventId = 9715,
        Level = LogLevel.Warning,
        Message = "logout_token must not contain 'nonce' claim (spec violation)")]
    public static partial void LogoutTokenContainsNonce(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9716,
        Level = LogLevel.Warning,
        Message = "logout_token missing 'jti' claim - required for replay protection")]
    public static partial void LogoutTokenMissingJti(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9717,
        Level = LogLevel.Warning,
        Message = "logout_token replay detected for jti: {Jti}")]
    public static partial void LogoutTokenReplayDetected(
        this ILogger logger,
        string jti);

    [LoggerMessage(
        EventId = 9718,
        Level = LogLevel.Warning,
        Message = "Back-channel logout rejected: unsupported Content-Type '{ContentType}'")]
    public static partial void InvalidContentType(
        this ILogger logger,
        string contentType);

    [LoggerMessage(
        EventId = 9719,
        Level = LogLevel.Warning,
        Message = "Back-channel logout rejected: missing or zero Content-Length")]
    public static partial void MissingContentLength(
        this ILogger logger);

    [LoggerMessage(
        EventId = 9720,
        Level = LogLevel.Warning,
        Message = "Back-channel logout rejected: Content-Length {Length} exceeds limit {Limit}")]
    public static partial void RequestBodyTooLarge(
        this ILogger logger,
        long length,
        long limit);

    [LoggerMessage(
        EventId = 9721,
        Level = LogLevel.Warning,
        Message = "Back-channel logout rejected: logout_token length {Length} exceeds limit {Limit}")]
    public static partial void LogoutTokenTooLong(
        this ILogger logger,
        int length,
        int limit);

    [LoggerMessage(
        EventId = 9722,
        Level = LogLevel.Warning,
        Message = "logout_token rejected: JWT header 'typ' was '{Typ}' but spec requires 'logout+jwt'")]
    public static partial void LogoutTokenInvalidTyp(
        this ILogger logger,
        string typ);
}
