using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace b17s.Porta.Auth.Discovery;

/// <summary>
/// Provides OIDC discovery document loading with automatic caching and refresh
/// </summary>
public interface IDiscoveryService
{
    /// <summary>
    /// Gets the OpenID Connect configuration for the specified authority
    /// </summary>
    /// <param name="authority">The OIDC authority URL</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>The OpenID Connect configuration, or null if unavailable</returns>
    Task<OpenIdConnectConfiguration?> GetConfigurationAsync(string authority, CancellationToken cancellationToken = default);
}
