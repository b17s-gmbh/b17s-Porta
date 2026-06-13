using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace b17s.Porta.Middleware;

/// <summary>
/// Middleware that handles Basic Authentication for specific endpoints.
/// Validates credentials against configured values.
/// </summary>
public sealed class BasicAuthMiddleware(RequestDelegate next, ILogger<BasicAuthMiddleware> logger)
{
    private const string AuthorizationHeaderName = "Authorization";
    private const string BasicScheme = "Basic";

    /// <summary>
    /// Processes the request, enforcing Basic authentication on endpoints marked with
    /// <see cref="RequireBasicAuthAttribute"/> and passing all other requests through unchanged.
    /// Credentials are compared in fixed time against <c>BasicAuth:Username</c> and
    /// <c>BasicAuth:Password</c> from configuration; on failure the client is challenged with a
    /// <c>401</c> and a <c>WWW-Authenticate: Basic</c> header.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="configuration">Application configuration supplying the expected credentials.</param>
    /// <returns>A task that completes when the request has been handled or passed to the next middleware.</returns>
    public async Task InvokeAsync(HttpContext context, IConfiguration configuration)
    {
        // Check if this endpoint requires basic auth
        var endpoint = context.GetEndpoint();
        var requiresBasicAuth = endpoint?.Metadata.GetMetadata<RequireBasicAuthAttribute>() != null;

        if (!requiresBasicAuth)
        {
            await next(context);
            return;
        }

        // Extract and validate credentials
        if (!context.Request.Headers.TryGetValue(AuthorizationHeaderName, out var authHeader))
        {
            logger.NoAuthorizationHeader();
            await ChallengeAsync(context);
            return;
        }

        try
        {
            AuthenticationHeaderValue authHeaderValue;
            try
            {
                authHeaderValue = AuthenticationHeaderValue.Parse(authHeader!);
            }
            catch (FormatException)
            {
                logger.MalformedAuthorizationHeader();
                await ChallengeAsync(context);
                return;
            }

            if (!string.Equals(authHeaderValue.Scheme, BasicScheme, StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(authHeaderValue.Parameter))
            {
                logger.InvalidAuthenticationScheme(authHeaderValue.Scheme);
                await ChallengeAsync(context);
                return;
            }

            byte[] credentialBytes;
            try
            {
                credentialBytes = Convert.FromBase64String(authHeaderValue.Parameter);
            }
            catch (FormatException)
            {
                logger.MalformedCredentials();
                await ChallengeAsync(context);
                return;
            }

            var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':', 2);

            if (credentials.Length != 2)
            {
                logger.InvalidCredentialsFormat();
                await ChallengeAsync(context);
                return;
            }

            var username = credentials[0];
            var password = credentials[1];

            // Validate against configuration
            var configUsername = configuration["BasicAuth:Username"];
            var configPassword = configuration["BasicAuth:Password"];

            if (string.IsNullOrEmpty(configUsername) || string.IsNullOrEmpty(configPassword))
            {
                logger.BasicAuthConfigurationMissing();
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response.WriteAsync("Authentication configuration error", context.RequestAborted);
                return;
            }

            var userHash = SHA256.HashData(Encoding.UTF8.GetBytes(username));
            var configUserHash = SHA256.HashData(Encoding.UTF8.GetBytes(configUsername));
            var passHash = SHA256.HashData(Encoding.UTF8.GetBytes(password));
            var configPassHash = SHA256.HashData(Encoding.UTF8.GetBytes(configPassword));

            var userOk = CryptographicOperations.FixedTimeEquals(userHash, configUserHash);
            var passOk = CryptographicOperations.FixedTimeEquals(passHash, configPassHash);

            if (!(userOk & passOk))
            {
                logger.InvalidCredentialsProvided(Convert.ToHexString(userHash, 0, 8));
                await ChallengeAsync(context);
                return;
            }

            // Authentication successful - store username in context
            context.Items["BasicAuthUsername"] = username;
            await next(context);
        }
        catch (Exception ex)
        {
            logger.BasicAuthenticationError(ex);
            await ChallengeAsync(context);
        }
    }

    private static Task ChallengeAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = "Basic realm=\"API\"";
        return context.Response.WriteAsync("Unauthorized", context.RequestAborted);
    }
}

/// <summary>
/// Attribute to mark endpoints that require basic authentication.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
public sealed class RequireBasicAuthAttribute : Attribute
{
}

/// <summary>
/// High-performance logging for BasicAuthMiddleware.
/// </summary>
internal static partial class BasicAuthMiddlewareLogging
{
    [LoggerMessage(EventId = 13400, Level = LogLevel.Warning,
        Message = "Basic auth required but no Authorization header provided")]
    public static partial void NoAuthorizationHeader(this ILogger logger);

    [LoggerMessage(EventId = 13401, Level = LogLevel.Warning,
        Message = "Invalid authentication scheme: {Scheme}")]
    public static partial void InvalidAuthenticationScheme(this ILogger logger, string scheme);

    [LoggerMessage(EventId = 13402, Level = LogLevel.Warning,
        Message = "Invalid credentials format")]
    public static partial void InvalidCredentialsFormat(this ILogger logger);

    [LoggerMessage(EventId = 13403, Level = LogLevel.Error,
        Message = "BasicAuth configuration is missing")]
    public static partial void BasicAuthConfigurationMissing(this ILogger logger);

    [LoggerMessage(EventId = 13404, Level = LogLevel.Warning,
        Message = "Invalid credentials provided for user (sha256 prefix): {UsernameHashPrefix}")]
    public static partial void InvalidCredentialsProvided(this ILogger logger, string usernameHashPrefix);

    [LoggerMessage(EventId = 13405, Level = LogLevel.Error,
        Message = "Error processing basic authentication")]
    public static partial void BasicAuthenticationError(this ILogger logger, Exception ex);

    [LoggerMessage(EventId = 13406, Level = LogLevel.Warning,
        Message = "Malformed Authorization header")]
    public static partial void MalformedAuthorizationHeader(this ILogger logger);

    [LoggerMessage(EventId = 13407, Level = LogLevel.Warning,
        Message = "Malformed base64 in basic auth credentials")]
    public static partial void MalformedCredentials(this ILogger logger);
}

/// <summary>
/// Extension methods for registering basic auth middleware.
/// </summary>
public static class BasicAuthMiddlewareExtensions
{
    /// <summary>
    /// Adds the <see cref="BasicAuthMiddleware"/> to the request pipeline, enforcing Basic
    /// authentication on endpoints marked with <see cref="RequireBasicAuthAttribute"/>.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The same <see cref="IApplicationBuilder"/> instance, for chaining.</returns>
    public static IApplicationBuilder UseBasicAuth(this IApplicationBuilder app)
        => app.UseMiddleware<BasicAuthMiddleware>();
}
