using System.Collections.Concurrent;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace b17s.Porta.Auth.Discovery;

/// <summary>
/// Provides OIDC discovery document loading with automatic caching and refresh.
/// Uses Microsoft.IdentityModel.Protocols.OpenIdConnect for proper cache management.
/// </summary>
public sealed class DiscoveryService(
    IHttpClientFactory httpClientFactory,
    IOptionsMonitor<SessionAuthenticationConfiguration> configMonitor,
    ILogger<DiscoveryService> logger,
    TimeProvider? timeProvider = null,
    IOptionsMonitor<ReferenceTokenAuthOptions>? referenceTokenOptionsMonitor = null) : IDiscoveryService
{
    /// <summary>
    /// Minimum time between forced refreshes per authority. The trigger (a token with an unknown
    /// <c>kid</c>) is attacker-controllable on the unauthenticated back-channel logout endpoint,
    /// so forced fetches must be rate-limited; a legitimate key rollover only needs one.
    /// </summary>
    internal static readonly TimeSpan ForcedRefreshMinInterval = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _managers = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastForcedRefresh = new();
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly FactoryDocumentRetriever _documentRetriever = new(httpClientFactory, configMonitor, referenceTokenOptionsMonitor);

    /// <inheritdoc/>
    public async Task<OpenIdConnectConfiguration?> GetConfigurationAsync(string authority, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(authority))
        {
            logger.DiscoveryAuthorityNullOrEmpty();
            return null;
        }

        var manager = GetOrCreateManager(authority);

        try
        {
            var config = await manager.GetConfigurationAsync(cancellationToken);
            logger.DiscoveryConfigurationLoaded(authority);
            return config;
        }
        catch (Exception ex) when (!ex.IsCanceledBy(cancellationToken))
        {
            logger.DiscoveryFailed(authority, ex);
            return null;
        }
    }

    /// <inheritdoc/>
    public async Task<OpenIdConnectConfiguration?> RefreshConfigurationAsync(string authority, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(authority) || !_managers.ContainsKey(authority))
        {
            return null;
        }

        var now = _timeProvider.GetUtcNow();
        if (_lastForcedRefresh.TryGetValue(authority, out var last) && now - last < ForcedRefreshMinInterval)
        {
            logger.DiscoveryForcedRefreshThrottled(authority);
            return null;
        }

        _lastForcedRefresh[authority] = now;

        try
        {
            // One-shot fetch awaited inline: ConfigurationManager.RequestRefresh only refreshes
            // on a background thread, but the caller needs the post-rollover keys *now*, for the
            // retry within the same request (back-channel logout gets a single delivery attempt).
            var config = await OpenIdConnectConfigurationRetriever.GetAsync(
                BuildMetadataAddress(authority),
                _documentRetriever,
                cancellationToken);

            // Drop the stale manager so every other consumer also sees post-rollover metadata
            // on their next call (a fresh manager re-fetches inline) instead of the stale cache.
            // Only on success - a failed refresh must keep the cached configuration usable.
            _managers.TryRemove(authority, out _);

            logger.DiscoveryConfigurationRefreshed(authority);
            return config;
        }
        catch (Exception ex) when (!ex.IsCanceledBy(cancellationToken))
        {
            logger.DiscoveryFailed(authority, ex);
            return null;
        }
    }

    /// <summary>
    /// Builds the OIDC metadata URL for an authority without normalising the authority's
    /// trailing slash. IdPs differ on whether they advertise <c>https://idp</c> or
    /// <c>https://idp/</c> as the issuer, and that exact string is what token validation
    /// compares against (RFC 7519). Silently trimming would shift trailing-slash drift from
    /// configuration time to token-validation time, so we preserve the configured form and
    /// only add the missing separator.
    /// </summary>
    public static string BuildMetadataAddress(string authority)
    {
        var separator = authority.EndsWith('/') ? string.Empty : "/";
        return authority + separator + ".well-known/openid-configuration";
    }

    private ConfigurationManager<OpenIdConnectConfiguration> GetOrCreateManager(string authority)
    {
        return _managers.GetOrAdd(authority, key =>
        {
            var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
                BuildMetadataAddress(key),
                new OpenIdConnectConfigurationRetriever(),
                _documentRetriever);

            logger.DiscoveryManagerCreated(key);
            return manager;
        });
    }

    /// <summary>
    /// Resolves a fresh <see cref="HttpClient"/> from the factory for every document fetch.
    /// The <see cref="ConfigurationManager{T}"/> instances live for the process lifetime, so
    /// pinning the client created at manager construction would defeat the factory's handler
    /// rotation (DNS refresh, connection recycling) for that authority forever. Reading the
    /// options monitors per fetch likewise lets a <c>RequireHttpsMetadata</c> change take
    /// effect without a restart.
    /// </summary>
    internal sealed class FactoryDocumentRetriever(
        IHttpClientFactory httpClientFactory,
        IOptionsMonitor<SessionAuthenticationConfiguration> configMonitor,
        IOptionsMonitor<ReferenceTokenAuthOptions>? referenceTokenOptionsMonitor = null) : IDocumentRetriever
    {
        public Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            // Require HTTPS only while BOTH the session-auth config and the reference-token options
            // ask for it; if EITHER path opts out, plain-http discovery is allowed for every fetch.
            // Both flags default to true, which is what makes this work for single-frontend BFFs: a
            // reference-token-only BFF flips ReferenceTokenAuthOptions.RequireHttpsMetadata=false
            // without touching the session-auth type (whose untouched default stays true), and a
            // session/OIDC-only BFF is unchanged (the ref-token monitor stays at its true default, or
            // is absent in direct construction). The trade-off is the rare mixed multi-frontend case
            // where one path opts out and the other does not: this shared fetcher can't tell which
            // authority a given fetch belongs to, so the opt-out downgrades discovery for both. That's
            // acceptable because RequireHttpsMetadata=false is a local-dev switch - in production every
            // path keeps the secure default and HTTPS stays enforced.
            var requireHttps = configMonitor.CurrentValue.RequireHttpsMetadata
                && (referenceTokenOptionsMonitor?.CurrentValue.RequireHttpsMetadata ?? true);

            var retriever = new HttpDocumentRetriever(
                httpClientFactory.CreateClient(AuthenticationServiceExtensions.TokenHttpClientName))
            {
                RequireHttps = requireHttps
            };
            return retriever.GetDocumentAsync(address, cancel);
        }
    }
}

/// <summary>
/// High-performance logging for DiscoveryService.
/// </summary>
internal static partial class DiscoveryServiceLogging
{
    [LoggerMessage(
        EventId = 13300,
        Level = LogLevel.Warning,
        Message = "Discovery authority is null or empty")]
    public static partial void DiscoveryAuthorityNullOrEmpty(this ILogger logger);

    [LoggerMessage(
        EventId = 13301,
        Level = LogLevel.Debug,
        Message = "Discovery configuration loaded for authority: {Authority}")]
    public static partial void DiscoveryConfigurationLoaded(this ILogger logger, string authority);

    [LoggerMessage(
        EventId = 13302,
        Level = LogLevel.Debug,
        Message = "Created discovery configuration manager for authority: {Authority}")]
    public static partial void DiscoveryManagerCreated(this ILogger logger, string authority);

    [LoggerMessage(
        EventId = 13303,
        Level = LogLevel.Error,
        Message = "Failed to load discovery configuration for authority: {Authority}")]
    public static partial void DiscoveryFailed(this ILogger logger, string authority, Exception ex);

    [LoggerMessage(
        EventId = 13304,
        Level = LogLevel.Information,
        Message = "Discovery metadata force-refreshed for authority: {Authority}")]
    public static partial void DiscoveryConfigurationRefreshed(this ILogger logger, string authority);

    [LoggerMessage(
        EventId = 13305,
        Level = LogLevel.Debug,
        Message = "Forced discovery refresh throttled for authority: {Authority}")]
    public static partial void DiscoveryForcedRefreshThrottled(this ILogger logger, string authority);
}
