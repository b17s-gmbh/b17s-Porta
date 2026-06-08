using System.Net.Http.Headers;
using System.Text;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Implements OAuth2 token revocation (RFC 7009).
/// Supports both provider-agnostic usage (with explicit options) and OIDC-configured usage.
/// </summary>
public sealed class TokenRevocationService(
    IHttpClientFactory httpClientFactory,
    IDiscoveryService discoveryService,
    IOptions<SessionAuthenticationConfiguration> configOptions,
    IOptions<PortaCoreOptions> coreOptions,
    ILogger<TokenRevocationService> logger) : ITokenRevocationService
{
    private readonly SessionAuthenticationConfiguration config = configOptions.Value;
    private readonly PortaCoreOptions _coreOptions = coreOptions.Value;

    /// <summary>
    /// Revokes a token using explicit provider-agnostic options.
    /// Use this method when you want to avoid OIDC-specific configuration coupling.
    /// </summary>
    public async Task<bool> RevokeTokenAsync(string token, TokenRevocationOptions options, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(token))
            return false;

        if (string.IsNullOrEmpty(options.RevocationEndpoint))
        {
            logger.RevocationEndpointNotConfigured();
            return false;
        }

        try
        {
            var httpClient = httpClientFactory.CreateClient(AuthenticationServiceExtensions.TokenHttpClientName);
            var request = new HttpRequestMessage(HttpMethod.Post, options.RevocationEndpoint);

            var payload = new Dictionary<string, string> { { "token", token } };
            if (!string.IsNullOrEmpty(tokenTypeHint))
                payload.Add("token_type_hint", tokenTypeHint);

            // Add client authentication (Basic auth preferred for confidential clients).
            // RFC 6749 §2.3.1: percent-encode client_id/client_secret before forming the
            // userid:password pair. RFC 7617: encode the pair as UTF-8 before base64.
            var encodedId = Uri.EscapeDataString(options.ClientId);
            var encodedSecret = Uri.EscapeDataString(options.ClientSecret);
            var credentials = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{encodedId}:{encodedSecret}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

            request.Content = new FormUrlEncodedContent(payload);
            var response = await httpClient.SendAsync(request, cancellationToken);

            if (response.IsSuccessStatusCode)
                return true;

            var errorContent = await IdpErrorBodyReader.ReadSafeAsync(response, _coreOptions, cancellationToken);
            logger.RevocationFailed((int)response.StatusCode, errorContent);
            return false;
        }
        catch (Exception ex) when (!ex.IsCanceledBy(cancellationToken))
        {
            logger.RevocationError(ex);
            return false;
        }
    }

    /// <summary>
    /// Revokes a token using the injected OIDC configuration.
    /// This overload uses OIDC discovery to find the revocation endpoint.
    /// </summary>
    public async Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(token))
            return false;

        if (string.IsNullOrEmpty(config.Authority))
        {
            logger.RevocationConfigurationMissing();
            return false;
        }

        try
        {
            var oidcConfig = await discoveryService.GetConfigurationAsync(config.Authority, cancellationToken);

            // Microsoft.IdentityModel deserializes `revocation_endpoint` (RFC 8414 / RFC 7009) into
            // the typed RevocationEndpoint property, so it is NOT present in AdditionalData. Reading
            // only AdditionalData here meant revocation silently no-op'd against every real IdP - the
            // refresh token was never revoked on logout/admin-termination. Prefer the typed value and
            // fall back to AdditionalData for parsers that surface it there instead.
            var revocationEndpoint = oidcConfig?.RevocationEndpoint;
            if (string.IsNullOrEmpty(revocationEndpoint))
            {
                revocationEndpoint = oidcConfig?.AdditionalData.TryGetValue("revocation_endpoint", out var endpoint) == true
                    ? endpoint?.ToString()
                    : null;
            }

            if (string.IsNullOrEmpty(revocationEndpoint))
            {
                logger.RevocationEndpointNotFound(config.Authority);
                return false;
            }

            // Validate client credentials
            if (string.IsNullOrEmpty(config.ClientId) || string.IsNullOrEmpty(config.ClientSecret))
            {
                logger.RevocationConfigurationMissing();
                return false;
            }

            // Delegate to the provider-agnostic method
            var options = new TokenRevocationOptions
            {
                RevocationEndpoint = revocationEndpoint,
                ClientId = config.ClientId,
                ClientSecret = config.ClientSecret
            };

            return await RevokeTokenAsync(token, options, tokenTypeHint, cancellationToken);
        }
        catch (Exception ex) when (!ex.IsCanceledBy(cancellationToken))
        {
            logger.RevocationError(ex);
            return false;
        }
    }

    /// <summary>
    /// Revokes multiple tokens using explicit provider-agnostic options.
    /// </summary>
    public Task<TokenRevocationBatchResult> RevokeTokensAsync(TokenRevocationOptions options, CancellationToken cancellationToken, params (string Token, string? TokenTypeHint)[] tokens)
        => RevokeBatchAsync(tokens, (token, hint) => RevokeTokenAsync(token, options, hint, cancellationToken));

    /// <summary>
    /// Revokes multiple tokens using the injected OIDC configuration.
    /// </summary>
    public Task<TokenRevocationBatchResult> RevokeTokensAsync(CancellationToken cancellationToken, params (string Token, string? TokenTypeHint)[] tokens)
        => RevokeBatchAsync(tokens, (token, hint) => RevokeTokenAsync(token, hint, cancellationToken));

    private static readonly TokenRevocationBatchResult EmptyBatch = new() { Outcomes = [] };

    private async Task<TokenRevocationBatchResult> RevokeBatchAsync(
        (string Token, string? TokenTypeHint)[] tokens,
        Func<string, string?, Task<bool>> revoke)
    {
        if (tokens == null || tokens.Length == 0)
            return EmptyBatch;

        // Revoke refresh tokens first: they are the long-lived, dangerous credential. If the
        // batch is interrupted (cancellation / host shutdown) part-way through, the most
        // important token has already been dealt with. Ordering is otherwise stable so the
        // outcome list still reflects the caller's intent.
        var ordered = tokens
            .Select((t, index) => (t.Token, t.TokenTypeHint, index))
            .OrderBy(t => t.TokenTypeHint == "refresh_token" ? 0 : 1)
            .ThenBy(t => t.index);

        var outcomes = new List<TokenRevocationOutcome>(tokens.Length);
        foreach (var (token, tokenTypeHint, _) in ordered)
        {
            var revoked = await revoke(token, tokenTypeHint);
            outcomes.Add(new TokenRevocationOutcome(tokenTypeHint, revoked));
        }

        var result = new TokenRevocationBatchResult { Outcomes = outcomes };
        if (!result.AllRevoked)
        {
            var successCount = outcomes.Count(o => o.Revoked);
            logger.BatchRevocationPartialFailure(successCount, outcomes.Count);
        }

        return result;
    }
}

/// <summary>
/// High-performance logging for TokenRevocationService.
/// </summary>
internal static partial class TokenRevocationServiceLogging
{
    [LoggerMessage(EventId = 14200, Level = LogLevel.Error,
        Message = "Token revocation failed: Authority not configured")]
    public static partial void RevocationConfigurationMissing(this ILogger logger);

    [LoggerMessage(EventId = 14201, Level = LogLevel.Error,
        Message = "Token revocation failed: revocation endpoint not found for authority {Authority}")]
    public static partial void RevocationEndpointNotFound(this ILogger logger, string authority);

    [LoggerMessage(EventId = 14202, Level = LogLevel.Warning,
        Message = "Token revocation failed: Status {StatusCode}, Error: {ErrorContent}")]
    public static partial void RevocationFailed(this ILogger logger, int statusCode, string errorContent);

    [LoggerMessage(EventId = 14203, Level = LogLevel.Error,
        Message = "Token revocation error")]
    public static partial void RevocationError(this ILogger logger, Exception ex);

    [LoggerMessage(EventId = 14204, Level = LogLevel.Warning,
        Message = "Batch token revocation partial failure: {SuccessCount}/{TotalCount} succeeded")]
    public static partial void BatchRevocationPartialFailure(this ILogger logger, int successCount, int totalCount);

    [LoggerMessage(EventId = 14205, Level = LogLevel.Error,
        Message = "Token revocation failed: revocation endpoint not configured in options")]
    public static partial void RevocationEndpointNotConfigured(this ILogger logger);
}
