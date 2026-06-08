using System.Collections.Concurrent;

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
    ILogger<DiscoveryService> logger) : IDiscoveryService
{
    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _managers = new();

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
            var metadataAddress = BuildMetadataAddress(key);
            var httpClient = httpClientFactory.CreateClient(AuthenticationServiceExtensions.TokenHttpClientName);

            var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(httpClient)
                {
                    RequireHttps = configMonitor.CurrentValue.RequireHttpsMetadata
                });

            logger.DiscoveryManagerCreated(key);
            return manager;
        });
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
}
