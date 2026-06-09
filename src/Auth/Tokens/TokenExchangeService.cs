using System.Net.Http.Json;

using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Provides OAuth token exchange functionality for API-specific tokens
/// </summary>
public sealed class TokenExchangeService(
    IHttpClientFactory httpClientFactory,
    IOptions<PortaCoreOptions> coreOptions,
    ILogger<TokenExchangeService> logger) : ITokenExchangeService
{
    private const string AccessTokenTypeUrn = "urn:ietf:params:oauth:token-type:access_token";

    private static readonly JsonWebTokenHandler JwtHandler = new();

    private readonly PortaCoreOptions _coreOptions = coreOptions.Value;

    /// <inheritdoc/>
    public async Task<TokenExchangeResult> ExchangeAsync(string accessToken, ApiConfiguration apiConfig, CancellationToken cancellationToken = default)
    {
        logger.TokenExchangeStarted(apiConfig.ApiPath, apiConfig.ApiScopes, apiConfig.ApiAudience);

        var httpClient = httpClientFactory.CreateClient(AuthenticationServiceExtensions.TokenHttpClientName);
        var scope = apiConfig.ApiScopes;

        // Get token endpoint - use API-specific endpoint if configured, otherwise use discovery
        var tokenEndpoint = apiConfig.TokenEndpoint;
        if (string.IsNullOrEmpty(tokenEndpoint))
        {
            logger.TokenEndpointNotConfigured(apiConfig.ApiPath);
            return TokenExchangeResult.Failure("Token endpoint must be configured either globally or per-API");
        }

        logger.UsingTokenEndpoint(tokenEndpoint);

        // Use per-API OAuth configuration
        if (string.IsNullOrEmpty(apiConfig.ClientId))
        {
            logger.ClientIdNotConfigured(apiConfig.ApiPath);
            return TokenExchangeResult.Failure("Client ID must be configured");
        }

        if (string.IsNullOrEmpty(apiConfig.ClientSecret))
        {
            logger.ClientSecretNotConfigured(apiConfig.ApiPath);
            return TokenExchangeResult.Failure("Client secret must be configured");
        }

        var clientId = apiConfig.ClientId;
        var clientSecret = apiConfig.ClientSecret;

        var grantType = "urn:ietf:params:oauth:grant-type:token-exchange";
        logger.BuildingTokenExchangeRequest(grantType);

        var dict = new Dictionary<string, string>
        {
            ["grant_type"] = grantType,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["subject_token"] = accessToken,
            ["scope"] = scope,
            ["audience"] = apiConfig.ApiAudience,
            ["requested_token_type"] = AccessTokenTypeUrn
        };

        logger.SendingTokenExchangeRequest(tokenEndpoint);

        try
        {
            var content = new FormUrlEncodedContent(dict);
            var httpResponse = await httpClient.PostAsync(tokenEndpoint, content, cancellationToken);

            if (!httpResponse.IsSuccessStatusCode)
            {
                logger.TokenExchangeFailed(apiConfig.ApiPath, (int)httpResponse.StatusCode);
                if (_coreOptions.LogIdpErrorBodies)
                {
                    var errorContent = await IdpErrorBodyReader.ReadSafeAsync(httpResponse, _coreOptions, cancellationToken);
                    logger.TokenExchangeErrorResponse(errorContent);
                }
                // Do not bake the response body into the failure string - verbose IdPs echo
                // refresh tokens / PII back here and this string surfaces in exception telemetry.
                return TokenExchangeResult.Failure($"Token exchange failed: {(int)httpResponse.StatusCode}");
            }

            logger.DeserializingTokenExchangeResponse(apiConfig.ApiPath);
            var response = await httpResponse.Content.ReadFromJsonAsync<TokenExchangeResponse>(cancellationToken);

            if (response == null)
            {
                logger.TokenExchangeResponseNull(apiConfig.ApiPath, tokenEndpoint);
                return TokenExchangeResult.Failure($"Error exchanging token at {tokenEndpoint}");
            }

            if (!ValidateExchangedToken(response, apiConfig))
            {
                return TokenExchangeResult.Failure($"Token exchange returned an untrusted token for {apiConfig.ApiPath}");
            }

            logger.TokenExchangeSuccessful(apiConfig.ApiPath, response.ExpiresIn);

            return TokenExchangeResult.Success(response);
        }
        catch (Exception ex) when (!ex.IsCanceledBy(cancellationToken))
        {
            logger.TokenExchangeException(ex, apiConfig.ApiPath);
            // Exception messages from System.Net.Http occasionally include the request URL
            // (which carries client_id/scope as query string in some IdP flows). Keep the
            // failure string opaque; the exception itself lands in structured logs.
            return TokenExchangeResult.Failure("Token exchange exception");
        }
    }

    /// <summary>
    /// Defense-in-depth validation of the STS response before the issued token is cached and
    /// forwarded downstream as the API token. The token endpoint is the BFF's own
    /// client-authenticated IdP over HTTPS, so this is not the primary trust boundary - it bounds
    /// the blast radius of a misconfigured or compromised STS that returns a token of the wrong
    /// type or for the wrong audience.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item><c>issued_token_type</c> is REQUIRED by RFC 8693 §2.2.1. We requested an access
    /// token, so a present-but-different URN (refresh/id token, arbitrary JWT) fails closed. An
    /// absent value is tolerated for not-strictly-compliant STSes.</item>
    /// <item>If the access token is a JWT, its <c>aud</c> must contain the configured
    /// <see cref="ApiConfiguration.ApiAudience"/>. Opaque (non-JWT) tokens are passed through -
    /// they cannot be checked here without introspection configuration.</item>
    /// </list>
    /// </remarks>
    private bool ValidateExchangedToken(TokenExchangeResponse response, ApiConfiguration apiConfig)
    {
        if (!string.IsNullOrEmpty(response.IssuedTokenType)
            && !string.Equals(response.IssuedTokenType, AccessTokenTypeUrn, StringComparison.Ordinal))
        {
            logger.TokenExchangeWrongTokenType(apiConfig.ApiPath, response.IssuedTokenType);
            return false;
        }

        if (!string.IsNullOrEmpty(apiConfig.ApiAudience)
            && TryReadJwt(response.AccessToken, out var jwt)
            && !jwt.Audiences.Contains(apiConfig.ApiAudience, StringComparer.Ordinal))
        {
            // Log the path and the expected (config-supplied) audience only; the token's actual
            // aud claim is treated as Secret-classified and must not reach the log stream.
            logger.TokenExchangeAudienceMismatch(apiConfig.ApiPath, apiConfig.ApiAudience);
            return false;
        }

        return true;
    }

    private static bool TryReadJwt(string token, out JsonWebToken jwt)
    {
        jwt = null!;
        if (string.IsNullOrEmpty(token) || !JwtHandler.CanReadToken(token))
        {
            return false;
        }

        try
        {
            jwt = JwtHandler.ReadJsonWebToken(token);
            return true;
        }
        catch (ArgumentException)
        {
            // Not a well-formed JWT despite CanReadToken's structural pre-check - treat as opaque.
            return false;
        }
    }
}

/// <summary>
/// High-performance logging for TokenExchangeService using compile-time source generators.
/// </summary>
internal static partial class TokenExchangeServiceLogging
{
    [LoggerMessage(
        EventId = 11300,
        Level = LogLevel.Information,
        Message = "Token exchange started for API: {ApiPath}, scopes: {ApiScopes}, audience: {ApiAudience}")]
    public static partial void TokenExchangeStarted(
        this ILogger logger,
        string apiPath,
        string? apiScopes,
        string? apiAudience);

    [LoggerMessage(
        EventId = 11301,
        Level = LogLevel.Warning,
        Message = "Token endpoint not configured for API: {ApiPath}")]
    public static partial void TokenEndpointNotConfigured(
        this ILogger logger,
        string apiPath);

    [LoggerMessage(
        EventId = 11302,
        Level = LogLevel.Debug,
        Message = "Using token endpoint: {TokenEndpoint}")]
    public static partial void UsingTokenEndpoint(
        this ILogger logger,
        string tokenEndpoint);

    [LoggerMessage(
        EventId = 11303,
        Level = LogLevel.Warning,
        Message = "Client ID not configured for API: {ApiPath}")]
    public static partial void ClientIdNotConfigured(
        this ILogger logger,
        string apiPath);

    [LoggerMessage(
        EventId = 11304,
        Level = LogLevel.Warning,
        Message = "Client secret not configured for API: {ApiPath}")]
    public static partial void ClientSecretNotConfigured(
        this ILogger logger,
        string apiPath);

    [LoggerMessage(
        EventId = 11305,
        Level = LogLevel.Debug,
        Message = "Building token exchange request with grant type: {GrantType}")]
    public static partial void BuildingTokenExchangeRequest(
        this ILogger logger,
        string grantType);

    [LoggerMessage(
        EventId = 11306,
        Level = LogLevel.Debug,
        Message = "Sending token exchange request to: {TokenEndpoint}")]
    public static partial void SendingTokenExchangeRequest(
        this ILogger logger,
        string tokenEndpoint);

    [LoggerMessage(
        EventId = 11307,
        Level = LogLevel.Warning,
        Message = "Token exchange failed for API: {ApiPath} with status code: {StatusCode}")]
    public static partial void TokenExchangeFailed(
        this ILogger logger,
        string apiPath,
        int statusCode);

    [LoggerMessage(
        EventId = 11308,
        Level = LogLevel.Debug,
        Message = "Token exchange error response: {ErrorContent}")]
    public static partial void TokenExchangeErrorResponse(
        this ILogger logger,
        string errorContent);

    [LoggerMessage(
        EventId = 11309,
        Level = LogLevel.Debug,
        Message = "Deserializing token exchange response for API: {ApiPath}")]
    public static partial void DeserializingTokenExchangeResponse(
        this ILogger logger,
        string apiPath);

    [LoggerMessage(
        EventId = 11310,
        Level = LogLevel.Error,
        Message = "Token exchange response is null for API: {ApiPath} from endpoint: {TokenEndpoint}")]
    public static partial void TokenExchangeResponseNull(
        this ILogger logger,
        string apiPath,
        string tokenEndpoint);

    [LoggerMessage(
        EventId = 11311,
        Level = LogLevel.Information,
        Message = "Token exchange successful for API: {ApiPath}, expires in: {ExpiresIn}s")]
    public static partial void TokenExchangeSuccessful(
        this ILogger logger,
        string apiPath,
        int expiresIn);

    [LoggerMessage(
        EventId = 11312,
        Level = LogLevel.Error,
        Message = "Token exchange exception for API: {ApiPath}")]
    public static partial void TokenExchangeException(
        this ILogger logger,
        Exception exception,
        string apiPath);

    [LoggerMessage(
        EventId = 11313,
        Level = LogLevel.Warning,
        Message = "Token exchange for API: {ApiPath} returned unexpected issued_token_type '{IssuedTokenType}'; expected an access token. Rejecting.")]
    public static partial void TokenExchangeWrongTokenType(
        this ILogger logger,
        string apiPath,
        string issuedTokenType);

    [LoggerMessage(
        EventId = 11314,
        Level = LogLevel.Warning,
        Message = "Token exchange for API: {ApiPath} returned a token whose audience does not contain the configured ApiAudience '{ExpectedAudience}'. Rejecting.")]
    public static partial void TokenExchangeAudienceMismatch(
        this ILogger logger,
        string apiPath,
        string expectedAudience);
}
