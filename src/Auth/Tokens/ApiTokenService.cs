using b17s.Porta.Auth.Sessions;
using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Provides API-specific token management with caching and refresh capabilities.
/// Token storage is handled by ITokenStorage which should be backed by distributed storage (e.g., Redis-backed session) for HA.
/// Supports both provider-agnostic usage (with explicit options) and OIDC-configured usage.
/// </summary>
public sealed class ApiTokenService(
    ITokenExchangeService tokenExchangeService,
    ITokenRefreshService tokenRefreshService,
    ITokenStorage tokenStorage,
    IOptions<SessionAuthenticationConfiguration> sessionAuthenticationConfigOptions,
    IOptions<PortaCoreOptions> coreOptions,
    ILogger<ApiTokenService> logger,
    TimeProvider? timeProvider = null,
    PortaMetrics? metrics = null) : IApiTokenService, IDisposable
{
    private readonly SessionAuthenticationConfiguration sessionAuthenticationConfig = sessionAuthenticationConfigOptions.Value;
    private readonly TimeSpan _refreshSkew = coreOptions.Value.TokenRefreshSkew;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    // Serializes access to the api-token cache. This service is scoped, so one gate per request is
    // shared by every consumer in that request (token-exchange handler, refresh service). The cache
    // lives in HttpContext.Session, which is not thread-safe, and a cache write is a read-modify-write
    // of a single session entry - without this, parallel TokenExchange aggregation legs would race and
    // lose each other's tokens. SemaphoreSlim because the guarded section is async (Lock cannot be held
    // across await).
    private readonly SemaphoreSlim _cacheGate = new(1, 1);

    /// <summary>
    /// Gets or creates an API-specific token using the injected session configuration.
    /// </summary>
    public Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, CancellationToken cancellationToken = default)
    {
        var cacheOptions = new ApiTokenCacheOptions
        {
            CacheKey = sessionAuthenticationConfig.SessionKeys.GetApiAccessTokenKey()
        };
        return GetApiTokenAsync(context, apiConfig, accessToken, cacheOptions, cancellationToken);
    }

    /// <summary>
    /// Gets or creates an API-specific token with explicit cache options.
    /// Use this method when you want to avoid coupling to SessionAuthenticationConfiguration.
    /// </summary>
    public async Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default)
    {
        using var activity = PortaActivitySource.Source.StartActivity(PortaActivitySource.Activities.TokenExchange);
        activity?.SetTag("api.path", apiConfig.ApiPath);
        activity?.SetTag("api.scopes", apiConfig.ApiScopes);

        logger.ApiTokenRequested(apiConfig.ApiPath, apiConfig.ApiScopes);

        if (string.IsNullOrEmpty(accessToken))
        {
            logger.AccessTokenNullForApi(apiConfig.ApiPath);
            // Fail closed - returning "" would cause the caller to forward
            // "Authorization: Bearer " and be silently treated as anonymous downstream.
            return null;
        }

        var cachedToken = await GetCachedApiTokenAsync(context, apiConfig, cacheOptions.CacheKey, cancellationToken);

        if (cachedToken != null)
        {
            if (cachedToken.IsExpiredWithSkew(_refreshSkew, _timeProvider) && !string.IsNullOrEmpty(cachedToken.RefreshToken))
            {
                logger.ApiTokenExpired(apiConfig.ApiPath);
                logger.ApiTokenRefreshing(apiConfig.ApiPath, apiConfig.ApiScopes);

                var refreshOptions = BuildRefreshOptions(apiConfig);
                if (refreshOptions == null)
                {
                    logger.ApiTokenRefreshReturnedNull(apiConfig.ApiPath);
                    await RemoveCachedApiTokenAsync(context, apiConfig, cacheOptions.CacheKey, cancellationToken);
                }
                else
                {
                    var refreshResult = await tokenRefreshService.RefreshAsync(cachedToken.RefreshToken, refreshOptions, cancellationToken);
                    var refreshResponse = refreshResult.Response;
                    if (refreshResponse != null)
                    {
                        var refreshedToken = new TokenExchangeResponse
                        {
                            AccessToken = refreshResponse.AccessToken,
                            RefreshToken = string.IsNullOrEmpty(refreshResponse.RefreshToken)
                                ? cachedToken.RefreshToken
                                : refreshResponse.RefreshToken,
                            ExpiresIn = refreshResponse.ExpiresIn,
                            IssuedAt = _timeProvider.GetUtcNow()
                        };

                        await SetCachedApiTokenAsync(context, apiConfig, refreshedToken, cacheOptions.CacheKey, cancellationToken);

                        logger.ApiTokenRefreshed(apiConfig.ApiPath);
                        metrics?.RecordTokenRefresh(success: true, reason: "api_token");
                        return refreshedToken.AccessToken;
                    }

                    logger.ApiTokenRefreshReturnedNull(apiConfig.ApiPath);
                    metrics?.RecordTokenRefresh(success: false, reason: "api_token");
                    await RemoveCachedApiTokenAsync(context, apiConfig, cacheOptions.CacheKey, cancellationToken);
                    // Fall through to perform new token exchange
                }
            }
            else if (!cachedToken.IsExpiredWithSkew(_refreshSkew, _timeProvider))
            {
                var remainingTtl = (cachedToken.IssuedAt.AddSeconds(cachedToken.ExpiresIn) - _timeProvider.GetUtcNow()).TotalSeconds;
                logger.ApiTokenCacheHit(apiConfig.ApiPath, remainingTtl);
                activity?.SetTag("cache.hit", true);
                return cachedToken.AccessToken;
            }
        }
        else
        {
            logger.ApiTokenCacheMiss(apiConfig.ApiPath);
            activity?.SetTag("cache.hit", false);
        }

        logger.ApiTokenExchangeStarted(apiConfig.ApiPath, apiConfig.ApiScopes);

        var exchangeResult = await tokenExchangeService.ExchangeAsync(accessToken, apiConfig, cancellationToken);
        if (exchangeResult.IsSuccess && exchangeResult.Response != null)
        {
            exchangeResult.Response.IssuedAt = _timeProvider.GetUtcNow();

            await SetCachedApiTokenAsync(context, apiConfig, exchangeResult.Response, cacheOptions.CacheKey, cancellationToken);

            logger.ApiTokenExchangeCompleted(apiConfig.ApiPath, exchangeResult.Response.ExpiresIn);
            return exchangeResult.Response.AccessToken;
        }

        logger.ApiTokenExchangeFailedWithError(apiConfig.ApiPath, exchangeResult.Error ?? "Unknown error");
        return null;
    }

    /// <summary>
    /// Invalidates cached API tokens using the injected session configuration.
    /// </summary>
    public Task InvalidateApiTokensAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        var cacheOptions = new ApiTokenCacheOptions
        {
            CacheKey = sessionAuthenticationConfig.SessionKeys.GetApiAccessTokenKey()
        };
        return InvalidateApiTokensAsync(context, cacheOptions, cancellationToken);
    }

    /// <summary>
    /// Invalidates cached API tokens with explicit cache options.
    /// Use this method when you want to avoid coupling to SessionAuthenticationConfiguration.
    /// </summary>
    public async Task InvalidateApiTokensAsync(HttpContext context, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default)
    {
        await _cacheGate.WaitAsync(cancellationToken);
        try
        {
            await tokenStorage.RemoveObjectAsync(context, cacheOptions.CacheKey);
        }
        finally
        {
            _cacheGate.Release();
        }
        logger.ApiTokensInvalidated();
    }

    private async Task<TokenExchangeResponse?> GetCachedApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string cacheKey, CancellationToken cancellationToken = default)
    {
        await _cacheGate.WaitAsync(cancellationToken);
        Dictionary<string, TokenExchangeResponse>? cache;
        try
        {
            cache = await tokenStorage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(context, cacheKey);
        }
        finally
        {
            _cacheGate.Release();
        }

        return cache != null && cache.TryGetValue(apiConfig.ApiPath, out var value) ? value : null;
    }

    private async Task RemoveCachedApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string cacheKey, CancellationToken cancellationToken = default)
    {
        // Drop only the failed ApiPath's entry - a single API's refresh failure must not
        // discard every other API's still-valid token in the per-session dictionary.
        await _cacheGate.WaitAsync(cancellationToken);
        try
        {
            var cache = await tokenStorage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(context, cacheKey);
            if (cache != null && cache.Remove(apiConfig.ApiPath))
            {
                await tokenStorage.SetObjectAsync(context, cacheKey, cache);
            }
        }
        finally
        {
            _cacheGate.Release();
        }
    }

    private async Task SetCachedApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, TokenExchangeResponse response, string cacheKey, CancellationToken cancellationToken = default)
    {
        // Read-merge-write under the gate so concurrent legs don't clobber each other's audiences:
        // re-reading the latest dict inside the critical section is what makes the merge atomic.
        await _cacheGate.WaitAsync(cancellationToken);
        try
        {
            var cache = await tokenStorage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(context, cacheKey)
                ?? [];
            cache[apiConfig.ApiPath] = response;
            await tokenStorage.SetObjectAsync(context, cacheKey, cache);
        }
        finally
        {
            _cacheGate.Release();
        }
    }

    /// <summary>
    /// Disposes the internal semaphore that serializes access to the per-request API-token cache.
    /// </summary>
    public void Dispose() => _cacheGate.Dispose();

    private static TokenRefreshOptions? BuildRefreshOptions(ApiConfiguration apiConfig)
    {
        if (string.IsNullOrEmpty(apiConfig.TokenEndpoint) ||
            string.IsNullOrEmpty(apiConfig.ClientId) ||
            string.IsNullOrEmpty(apiConfig.ClientSecret))
        {
            return null;
        }

        return new TokenRefreshOptions
        {
            TokenEndpoint = apiConfig.TokenEndpoint,
            ClientId = apiConfig.ClientId,
            ClientSecret = apiConfig.ClientSecret,
            Scope = string.IsNullOrEmpty(apiConfig.ApiScopes) ? null : apiConfig.ApiScopes,
        };
    }
}

/// <summary>
/// High-performance logging for ApiTokenService using compile-time source generators.
/// </summary>
internal static partial class ApiTokenServiceLogging
{
    [LoggerMessage(
        EventId = 11000,
        Level = LogLevel.Debug,
        Message = "Getting API token for API path: {ApiPath}, scopes: {ApiScopes}")]
    public static partial void ApiTokenRequested(
        this ILogger logger,
        string apiPath,
        string? apiScopes);

    [LoggerMessage(
        EventId = 11001,
        Level = LogLevel.Warning,
        Message = "Access token is null or empty for API: {ApiPath}")]
    public static partial void AccessTokenNullForApi(
        this ILogger logger,
        string apiPath);

    [LoggerMessage(
        EventId = 11002,
        Level = LogLevel.Debug,
        Message = "API token cache hit for: {ApiPath}, remaining TTL: {RemainingTtlSeconds}s")]
    public static partial void ApiTokenCacheHit(
        this ILogger logger,
        string apiPath,
        double remainingTtlSeconds);

    [LoggerMessage(
        EventId = 11003,
        Level = LogLevel.Debug,
        Message = "API token cache miss for: {ApiPath}")]
    public static partial void ApiTokenCacheMiss(
        this ILogger logger,
        string apiPath);

    [LoggerMessage(
        EventId = 11004,
        Level = LogLevel.Debug,
        Message = "API token expired for: {ApiPath}, attempting refresh")]
    public static partial void ApiTokenExpired(
        this ILogger logger,
        string apiPath);

    [LoggerMessage(
        EventId = 11005,
        Level = LogLevel.Debug,
        Message = "Refreshing expired API token for API: {ApiPath}, scopes: {ApiScopes}")]
    public static partial void ApiTokenRefreshing(
        this ILogger logger,
        string apiPath,
        string? apiScopes);

    [LoggerMessage(
        EventId = 11006,
        Level = LogLevel.Debug,
        Message = "Successfully refreshed API token for: {ApiPath}")]
    public static partial void ApiTokenRefreshed(
        this ILogger logger,
        string apiPath);

    [LoggerMessage(
        EventId = 11007,
        Level = LogLevel.Warning,
        Message = "Token refresh returned null for API: {ApiPath}, invalidating cache and performing new token exchange")]
    public static partial void ApiTokenRefreshReturnedNull(
        this ILogger logger,
        string apiPath);

    [LoggerMessage(
        EventId = 11009,
        Level = LogLevel.Debug,
        Message = "Performing token exchange for API: {ApiPath}, scopes: {ApiScopes}")]
    public static partial void ApiTokenExchangeStarted(
        this ILogger logger,
        string apiPath,
        string? apiScopes);

    [LoggerMessage(
        EventId = 11010,
        Level = LogLevel.Debug,
        Message = "Successfully obtained API token for: {ApiPath}, expires in: {ExpiresIn}s")]
    public static partial void ApiTokenExchangeCompleted(
        this ILogger logger,
        string apiPath,
        int expiresIn);

    [LoggerMessage(
        EventId = 11013,
        Level = LogLevel.Error,
        Message = "Failed to obtain API token for: {ApiPath}. Error: {Error}. Returning null (fail-closed); the request will not be forwarded with a token")]
    public static partial void ApiTokenExchangeFailedWithError(
        this ILogger logger,
        string apiPath,
        string error);

    [LoggerMessage(
        EventId = 11012,
        Level = LogLevel.Debug,
        Message = "Invalidated API tokens from storage")]
    public static partial void ApiTokensInvalidated(
        this ILogger logger);
}
