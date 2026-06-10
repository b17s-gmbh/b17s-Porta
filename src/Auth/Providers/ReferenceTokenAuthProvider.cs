using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Services;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Auth.Providers;

/// <summary>
/// Reference token (opaque token) authentication provider.
/// Validates tokens via introspection endpoint with caching.
/// </summary>
public sealed class ReferenceTokenAuthProvider(
    IReferenceTokenService referenceTokenService,
    IDistributedCache cache,
    ILogger<ReferenceTokenAuthProvider> logger,
    IOptionsMonitor<ReferenceTokenAuthOptions> optionsMonitor,
    TimeProvider? timeProvider = null) : IAuthenticationProvider
{
    // Read CurrentValue per request so that appsettings.json reloads (rotating
    // ClientSecret, adding a ValidAudience) take effect without a process restart.
    private ReferenceTokenAuthOptions Options => optionsMonitor.CurrentValue;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <inheritdoc/>
    public async Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        var options = Options;
        var authContext = new AuthenticationContext();

        // Extract token from header
        var authHeader = context.Request.Headers[options.TokenHeaderName].FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith(options.TokenPrefix))
            return authContext;

        var token = authHeader[options.TokenPrefix.Length..].Trim();
        authContext.AccessToken = token;

        // Check cache first. The cache stores the raw introspection response (the AS's
        // active/claims verdict), which is stable for the token's lifetime; binding
        // (audience/issuer/client_id) is re-validated against the CurrentValue options
        // on every hit so that tightening ValidAudiences/ValidClientIds/ValidIssuers or
        // the validation flags takes effect immediately rather than waiting for the entry
        // to expire. Negative entries short-circuit to a failed context to prevent
        // unbounded introspection traffic for revoked / unknown tokens.
        var cacheKey = BuildIntrospectionCacheKey(token);
        var cachedData = await cache.GetStringAsync(cacheKey, cancellationToken);
        if (!string.IsNullOrEmpty(cachedData))
        {
            ReferenceTokenIntrospectionResult? cachedResult;
            try
            {
                cachedResult = JsonSerializer.Deserialize<ReferenceTokenIntrospectionResult>(cachedData);
            }
            catch (JsonException ex)
            {
                // Corrupt entry (old shape, partial write, attacker-injected). Evict and
                // treat as a cache miss - without this catch, every request for the same
                // token rethrows JsonException and breaks all logins until the entry expires.
                logger.CorruptIntrospectionCacheEntry(ex);
                await cache.RemoveAsync(cacheKey, cancellationToken);
                cachedResult = null;
            }

            if (cachedResult?.IsActive == true)
            {
                // Re-run binding against the current options. A cached active verdict does
                // not grant a free pass past audience/issuer/client_id checks that may have
                // been tightened since the entry was written.
                if (ValidateBinding(cachedResult, options))
                {
                    PopulateAuthContextFromResult(authContext, cachedResult);
                    return authContext;
                }

                authContext.AccessToken = null;
                authContext.Claims.Clear();
                return authContext;
            }
            if (cachedResult is not null)
            {
                authContext.AccessToken = null;
                return authContext;
            }
        }

        // Introspect the token
        try
        {
            var introspectionResult = await referenceTokenService.IntrospectTokenAsync(token, cancellationToken);

            if (introspectionResult is null)
            {
                // Introspection produced no verdict (IdP error after retries, missing endpoint,
                // oversized response). Fail closed, but do NOT negative-cache: caching this as
                // "inactive" would keep rejecting a valid token for NegativeCacheDuration during
                // an IdP outage. The next request retries against the IdP instead.
                logger.IntrospectionUnavailable();
                authContext.AccessToken = null;
                return authContext;
            }

            if (!introspectionResult.IsActive)
            {
                logger.TokenNotActive();
                authContext.AccessToken = null;
                await CacheNegativeResultAsync(cacheKey, options, cancellationToken);
                return authContext;
            }

            if (!ValidateBinding(introspectionResult, options))
            {
                authContext.AccessToken = null;
                authContext.Claims.Clear();
                await CacheNegativeResultAsync(cacheKey, options, cancellationToken);
                return authContext;
            }

            PopulateAuthContextFromResult(authContext, introspectionResult);

            var cacheDuration = CalculateCacheDuration(introspectionResult, options);
            await cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(introspectionResult),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = cacheDuration
                }, cancellationToken);
        }
        catch (Exception ex) when (!ex.IsCanceledBy(cancellationToken))
        {
            logger.IntrospectionError(ex);
            authContext.AccessToken = null;
        }

        return authContext;
    }

    /// <summary>
    /// Verifies that the introspection response is bound to this BFF - that the token's
    /// <c>aud</c>/<c>client_id</c> appears in the configured allow-lists, and that <c>iss</c>
    /// matches the configured authority/issuers. RFC 7662 <c>active=true</c> only states that
    /// the AS recognizes the token as live; without these checks any active token from the
    /// same authority for any other relying party would be accepted (audience confusion).
    /// </summary>
    private bool ValidateBinding(ReferenceTokenIntrospectionResult result, ReferenceTokenAuthOptions options)
    {
        if (options.ValidateAudience)
        {
            var audClaim = result.Claims.GetValueOrDefault("aud");
            var clientIdClaim = result.Claims.GetValueOrDefault("client_id");

            var audMatches = !string.IsNullOrEmpty(audClaim)
                && options.ValidAudiences.Count > 0
                && AudienceContainsAny(audClaim, options.ValidAudiences, logger);

            var clientIdMatches = !string.IsNullOrEmpty(clientIdClaim)
                && options.ValidClientIds.Count > 0
                && options.ValidClientIds.Contains(clientIdClaim, StringComparer.Ordinal);

            if (!audMatches && !clientIdMatches)
            {
                logger.AudienceMismatch(audClaim ?? string.Empty, clientIdClaim ?? string.Empty);
                return false;
            }
        }

        if (options.ValidateIssuer)
        {
            var issClaim = result.Claims.GetValueOrDefault("iss");
            if (string.IsNullOrEmpty(issClaim))
            {
                logger.IssuerMissing();
                return false;
            }

            IEnumerable<string> allowed = options.ValidIssuers.Count > 0
                ? options.ValidIssuers
                : string.IsNullOrEmpty(options.Authority)
                    ? Array.Empty<string>()
                    : [options.Authority];

            // Ordinal byte-for-byte match per RFC 7519. Authority is opaque: a trailing-slash
            // mismatch between configured value and IdP-emitted iss is a configuration bug we
            // surface here rather than paper over, because IdPs vary on which form they emit.
            if (!allowed.Contains(issClaim, StringComparer.Ordinal))
            {
                logger.IssuerMismatch(issClaim);
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// The introspection <c>aud</c> claim is rendered into the result dictionary either as a bare
    /// string (single audience) or as a JSON array (multiple audiences) by
    /// <see cref="b17s.Porta.Services.ReferenceTokenService"/>. RFC 7662 / RFC 7519 permit both forms
    /// on the wire; the producer normalises to one of these two encodings so this validator can
    /// decode unambiguously.
    /// </summary>
    private static bool AudienceContainsAny(string audClaim, IList<string> expected, ILogger logger)
    {
        if (string.IsNullOrEmpty(audClaim))
        {
            return false;
        }

        // Fast path: most bare-string audiences ("api://orders") aren't valid JSON,
        // so skip the parser. Only attempt JSON if it begins with '[' or '"' - the
        // only two shapes the producer ever emits for the multi-form encoding.
        var first = audClaim[0];
        if (first == '[' || first == '"')
        {
            try
            {
                using var doc = JsonDocument.Parse(audClaim);
                switch (doc.RootElement.ValueKind)
                {
                    case JsonValueKind.Array:
                        foreach (var element in doc.RootElement.EnumerateArray())
                        {
                            if (element.ValueKind != JsonValueKind.String) continue;
                            var value = element.GetString();
                            if (value is not null && expected.Contains(value, StringComparer.Ordinal))
                                return true;
                        }
                        return false;
                    case JsonValueKind.String:
                        var single = doc.RootElement.GetString();
                        return single is not null && expected.Contains(single, StringComparer.Ordinal);
                }
            }
            catch (JsonException)
            {
                // Started with a JSON delimiter but failed to parse; fall through to
                // bare-string comparison. Debug breadcrumb only, no payload - a malformed
                // audience value must never reach the (Secret-classified) log stream.
                logger.AudienceClaimMalformedJson();
            }
        }

        return expected.Contains(audClaim, StringComparer.Ordinal);
    }

    /// <summary>
    /// Reference tokens don't support refresh - they are validated via introspection each time.
    /// </summary>
    public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default) => Task.FromResult<AuthenticationContext?>(null);

    /// <inheritdoc/>
    public async Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        var options = Options;
        var authHeader = context.Request.Headers[options.TokenHeaderName].FirstOrDefault();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith(options.TokenPrefix))
        {
            var token = authHeader[options.TokenPrefix.Length..].Trim();
            await cache.RemoveAsync(BuildIntrospectionCacheKey(token), cancellationToken);
        }
    }

    /// <summary>
    /// Builds the introspection cache key as <c>introspection_{SHA256(token)}</c>. The raw
    /// bearer token is never used verbatim as a key, so anyone with cache read access
    /// (co-tenants, operators running KEYS/SCAN/MONITOR, backups, replicas) cannot enumerate
    /// or replay live tokens from the keyspace.
    /// </summary>
    internal static string BuildIntrospectionCacheKey(string token)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return $"introspection_{Convert.ToHexString(digest)}";
    }

    private static void PopulateAuthContextFromResult(AuthenticationContext authContext, ReferenceTokenIntrospectionResult result)
    {
        authContext.ExpiresAt = result.ExpiresAt;

        foreach (var claim in result.Claims)
        {
            // Introspection results are already flattened to a single value per claim type
            // (multi-valued aud is JSON-encoded into one string upstream), so wrap as a
            // one-element array to match the multi-valued AuthenticationContext.Claims shape.
            authContext.Claims[claim.Key] = [claim.Value];
        }
    }

    private async Task CacheNegativeResultAsync(string cacheKey, ReferenceTokenAuthOptions options, CancellationToken cancellationToken)
    {
        if (options.NegativeCacheDuration <= TimeSpan.Zero)
            return;

        var payload = JsonSerializer.Serialize(new ReferenceTokenIntrospectionResult { IsActive = false });
        await cache.SetStringAsync(cacheKey, payload,
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = options.NegativeCacheDuration
            }, cancellationToken);
    }

    private TimeSpan CalculateCacheDuration(ReferenceTokenIntrospectionResult result, ReferenceTokenAuthOptions options)
    {
        if (!result.ExpiresAt.HasValue)
            return options.DefaultCacheDuration;

        var duration = result.ExpiresAt.Value - _timeProvider.GetUtcNow() - TimeSpan.FromSeconds(30); // 30s buffer

        if (duration < TimeSpan.FromSeconds(10))
            return TimeSpan.FromSeconds(10);
        if (duration > options.MaxCacheDuration)
            return options.MaxCacheDuration;

        return duration;
    }
}

/// <summary>
/// High-performance logging for ReferenceTokenAuthProvider.
/// </summary>
internal static partial class ReferenceTokenAuthProviderLogging
{
    [LoggerMessage(EventId = 13503, Level = LogLevel.Warning,
        Message = "Reference token is not active")]
    public static partial void TokenNotActive(this ILogger logger);

    [LoggerMessage(EventId = 13510, Level = LogLevel.Warning,
        Message = "Token introspection returned no verdict (IdP error or misconfiguration); failing closed without negative-caching")]
    public static partial void IntrospectionUnavailable(this ILogger logger);

    [LoggerMessage(EventId = 13504, Level = LogLevel.Error,
        Message = "Token introspection error")]
    public static partial void IntrospectionError(this ILogger logger, Exception ex);

    [LoggerMessage(EventId = 13505, Level = LogLevel.Warning,
        Message = "Reference token rejected: aud='{Audience}' client_id='{ClientId}' did not match any configured ValidAudiences/ValidClientIds")]
    public static partial void AudienceMismatch(this ILogger logger, string audience, string clientId);

    [LoggerMessage(EventId = 13506, Level = LogLevel.Warning,
        Message = "Reference token rejected: introspection response missing 'iss' claim")]
    public static partial void IssuerMissing(this ILogger logger);

    [LoggerMessage(EventId = 13507, Level = LogLevel.Warning,
        Message = "Reference token rejected: iss='{Issuer}' did not match the configured authority/issuers")]
    public static partial void IssuerMismatch(this ILogger logger, string issuer);

    [LoggerMessage(EventId = 13508, Level = LogLevel.Warning,
        Message = "Discarding corrupt introspection cache entry (old shape or partial write); evicting and re-introspecting")]
    public static partial void CorruptIntrospectionCacheEntry(this ILogger logger, Exception ex);

    [LoggerMessage(EventId = 13509, Level = LogLevel.Debug,
        Message = "Audience claim began with a JSON delimiter but failed to parse; falling back to exact-string match")]
    public static partial void AudienceClaimMalformedJson(this ILogger logger);
}
