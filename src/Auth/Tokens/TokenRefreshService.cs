using System.Net.Http.Json;
using System.Text.Json;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Provides token refresh functionality for maintaining authentication state.
/// Supports both provider-agnostic usage (with explicit options) and OIDC-configured usage.
/// </summary>
public sealed class TokenRefreshService(
    IHttpClientFactory httpClientFactory,
    IDiscoveryService discoveryService,
    IOptions<SessionAuthenticationConfiguration> configOptions,
    IOptions<PortaCoreOptions> coreOptions,
    ILogger<TokenRefreshService> logger) : ITokenRefreshService
{
    public const string HttpClientName = AuthenticationServiceExtensions.TokenHttpClientName;

    private readonly SessionAuthenticationConfiguration config = configOptions.Value;
    private readonly PortaCoreOptions _coreOptions = coreOptions.Value;

    /// <summary>
    /// Refreshes an access token using explicit provider-agnostic options.
    /// Use this method when you want to avoid OIDC-specific configuration coupling.
    /// </summary>
    public async Task<RefreshTokenResult> RefreshAsync(string refreshToken, TokenRefreshOptions options, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(refreshToken))
        {
            logger.RefreshTokenMissing();
            return RefreshTokenResult.Transient();
        }

        if (string.IsNullOrEmpty(options.TokenEndpoint))
        {
            logger.TokenEndpointNotConfigured();
            return RefreshTokenResult.Transient();
        }

        try
        {
            var httpClient = httpClientFactory.CreateClient(HttpClientName);

            var payload = new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken },
                { "client_id", options.ClientId },
                { "client_secret", options.ClientSecret }
            };

            if (!string.IsNullOrEmpty(options.Scope))
            {
                payload.Add("scope", options.Scope);
            }

            var request = new HttpRequestMessage(HttpMethod.Post, options.TokenEndpoint)
            {
                Content = new FormUrlEncodedContent(payload)
            };

            var response = await httpClient.SendAsync(request, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                // Classify the OAuth2 error code first so a revoked/expired refresh token
                // (invalid_grant) is reported as a dead session rather than collapsed to a
                // transient failure - otherwise the caller would keep serving the stale
                // access token until it too expires.
                var reason = await ClassifyRefreshFailureAsync(response, cancellationToken);

                // The body is gated behind LogIdpErrorBodies - verbose IdPs echo the submitted
                // refresh token / client secret back inside error JSON, and we must not let
                // that hit log sinks by default.
                var errorContent = await IdpErrorBodyReader.ReadSafeAsync(response, _coreOptions, cancellationToken);
                logger.RefreshFailed((int)response.StatusCode, errorContent);

                return reason == RefreshFailureReason.InvalidGrant
                    ? RefreshTokenResult.InvalidGrant()
                    : RefreshTokenResult.Transient();
            }

            var result = await response.Content.ReadFromJsonAsync<TokenExchangeResponse>(cancellationToken);
            if (result == null)
            {
                logger.RefreshResponseInvalid();
                return RefreshTokenResult.Transient();
            }

            logger.RefreshSucceeded(result.ExpiresIn);
            return RefreshTokenResult.Success(result);
        }
        catch (Exception ex) when (!ex.IsCanceledBy(cancellationToken))
        {
            logger.RefreshError(ex);
            return RefreshTokenResult.Transient();
        }
    }

    /// <summary>
    /// Classifies an OAuth2 token-endpoint error response. A body carrying the standard
    /// <c>invalid_grant</c> error code (RFC 6749 §5.2) means the refresh token itself is no
    /// longer valid - revoked, expired, or rotated out - so retrying cannot help and the
    /// session is dead. Everything else (5xx, other error codes, an unparseable body) is
    /// treated as transient. Only the non-secret <c>error</c> field is inspected; the rest of
    /// the body is never read into logs (that path stays gated behind LogIdpErrorBodies).
    /// </summary>
    private static async Task<RefreshFailureReason> ClassifyRefreshFailureAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(body))
            {
                return RefreshFailureReason.Transient;
            }

            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("error", out var error)
                && error.ValueKind == JsonValueKind.String
                && string.Equals(error.GetString(), "invalid_grant", StringComparison.Ordinal))
            {
                return RefreshFailureReason.InvalidGrant;
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or HttpRequestException or IOException)
        {
            // Non-JSON or unreadable body: we cannot prove the grant is dead, so fail "transient"
            // (serve the current token / retry) rather than forcing a sign-out on a parse hiccup.
        }

        return RefreshFailureReason.Transient;
    }

    /// <summary>
    /// Refreshes an access token using the injected OIDC configuration.
    /// This overload uses OIDC discovery to find the token endpoint.
    /// </summary>
    public async Task<RefreshTokenResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(refreshToken))
        {
            logger.RefreshTokenMissing();
            return RefreshTokenResult.Transient();
        }

        // Validate configuration
        if (string.IsNullOrEmpty(config.Authority) ||
            string.IsNullOrEmpty(config.ClientId) ||
            string.IsNullOrEmpty(config.ClientSecret))
        {
            logger.RefreshConfigurationMissing();
            return RefreshTokenResult.Transient();
        }

        // Get token endpoint from discovery
        var oidcConfig = await discoveryService.GetConfigurationAsync(config.Authority, cancellationToken);
        if (oidcConfig == null || string.IsNullOrEmpty(oidcConfig.TokenEndpoint))
        {
            logger.TokenEndpointNotFound(config.Authority);
            return RefreshTokenResult.Transient();
        }

        // Delegate to the provider-agnostic method
        var options = new TokenRefreshOptions
        {
            TokenEndpoint = oidcConfig.TokenEndpoint,
            ClientId = config.ClientId,
            ClientSecret = config.ClientSecret,
            Scope = config.Scope
        };

        return await RefreshAsync(refreshToken, options, cancellationToken);
    }
}

/// <summary>
/// High-performance logging for TokenRefreshService.
/// </summary>
internal static partial class TokenRefreshServiceLogging
{
    [LoggerMessage(EventId = 14100, Level = LogLevel.Warning,
        Message = "Token refresh skipped: refresh token is missing")]
    public static partial void RefreshTokenMissing(this ILogger logger);

    [LoggerMessage(EventId = 14101, Level = LogLevel.Error,
        Message = "Token refresh failed: Authority, ClientId, or ClientSecret not configured")]
    public static partial void RefreshConfigurationMissing(this ILogger logger);

    [LoggerMessage(EventId = 14102, Level = LogLevel.Error,
        Message = "Token refresh failed: token endpoint not found for authority {Authority}")]
    public static partial void TokenEndpointNotFound(this ILogger logger, string authority);

    [LoggerMessage(EventId = 14103, Level = LogLevel.Warning,
        Message = "Token refresh failed: Status {StatusCode}, Error: {ErrorContent}")]
    public static partial void RefreshFailed(this ILogger logger, int statusCode, string errorContent);

    [LoggerMessage(EventId = 14104, Level = LogLevel.Warning,
        Message = "Token refresh failed: response deserialization returned null")]
    public static partial void RefreshResponseInvalid(this ILogger logger);

    [LoggerMessage(EventId = 14105, Level = LogLevel.Information,
        Message = "Token refresh successful, expires in {ExpiresIn}s")]
    public static partial void RefreshSucceeded(this ILogger logger, int expiresIn);

    [LoggerMessage(EventId = 14106, Level = LogLevel.Error,
        Message = "Token refresh error")]
    public static partial void RefreshError(this ILogger logger, Exception ex);

    [LoggerMessage(EventId = 14107, Level = LogLevel.Error,
        Message = "Token refresh failed: token endpoint not configured in options")]
    public static partial void TokenEndpointNotConfigured(this ILogger logger);
}
