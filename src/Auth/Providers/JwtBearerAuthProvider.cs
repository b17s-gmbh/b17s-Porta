using b17s.Porta.Auth.Tokens;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace b17s.Porta.Auth.Providers;

/// <summary>
/// JWT bearer authentication provider. Validates inbound JWTs using ASP.NET Core's built-in
/// JwtBearer authentication handler.
/// </summary>
/// <remarks>
/// This provider is opt-in. Reference token authentication remains the recommended default - see the
/// "Reference Tokens vs JWT" section of the README. Use this provider when your environment issues
/// JWTs and reference-token introspection is not available.
/// </remarks>
public sealed class JwtBearerAuthProvider(ILogger<JwtBearerAuthProvider> logger) : IAuthenticationProvider
{
    /// <inheritdoc/>
    public async Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        // 1. Ask ASP.NET Core's built-in JwtBearer handler to authenticate the request.
        // This validates the signature, issuer, audience, and lifetime using the robust
        // ConfigurationManager built into AddJwtBearer.
        var authResult = await context.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);

        if (!authResult.Succeeded || authResult.Principal == null)
        {
            if (authResult.Failure != null)
            {
                logger.JwtValidationFailed(authResult.Failure.Message);
            }
            return AuthenticationContext.Unauthenticated();
        }

        // 2. Extract the raw token that AddJwtBearer validated and saved.
        // This requires SaveToken = true in the AddJwtBearer options.
        var token = authResult.Properties?.GetTokenValue("access_token");
        if (string.IsNullOrEmpty(token))
        {
            logger.JwtMissingToken();
            return AuthenticationContext.Unauthenticated();
        }

        var authContext = new AuthenticationContext
        {
            AccessToken = token,
            ExpiresAt = authResult.Properties?.ExpiresUtc
        };

        // Group by type so multi-valued claims (e.g. multiple role claims) are all preserved
        // rather than collapsed to whichever happened to be enumerated last.
        foreach (var group in authResult.Principal.Claims.GroupBy(c => c.Type))
        {
            authContext.Claims[group.Key] = group.Select(c => c.Value).ToArray();
        }

        return authContext;
    }

    /// <summary>
    /// JWTs are stateless and validated per request - there is no refresh flow to invoke here.
    /// </summary>
    public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default) =>
        Task.FromResult<AuthenticationContext?>(null);

    /// <summary>
    /// JWTs cannot be invalidated server-side; the client must stop sending the token (and rely on
    /// short token lifetimes for revocation).
    /// </summary>
    public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default) => Task.CompletedTask;
}

/// <summary>
/// High-performance logging for JwtBearerAuthProvider.
/// </summary>
internal static partial class JwtBearerAuthProviderLogging
{
    [LoggerMessage(EventId = 13511, Level = LogLevel.Warning,
        Message = "JWT validation failed: {Reason}")]
    public static partial void JwtValidationFailed(this ILogger logger, string reason);

    [LoggerMessage(EventId = 13513, Level = LogLevel.Warning,
        Message = "JWT rejected: AuthenticateResult succeeded but no raw token was saved in properties (ensure SaveToken=true in JwtBearerOptions)")]
    public static partial void JwtMissingToken(this ILogger logger);
}
