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

    /// <summary>
    /// Fetches fresh discovery metadata (including JWKS signing keys) for the specified authority,
    /// bypassing the cache. Used to recover from IdP signing-key rollover: when token validation
    /// fails because the signing key is not in the cached key set, callers refresh and retry once
    /// against the returned fresh configuration.
    /// </summary>
    /// <param name="authority">The OIDC authority URL whose metadata should be re-fetched</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>
    /// The freshly fetched configuration, or <see langword="null"/> when the refresh was throttled,
    /// the fetch failed, or no metadata has ever been loaded for the authority.
    /// </returns>
    /// <remarks>
    /// Implementations must throttle forced refreshes per authority: the trigger (a token with an
    /// unknown <c>kid</c>) is attacker-controllable on unauthenticated endpoints such as back-channel
    /// logout, and an unthrottled refresh would let forged tokens drive metadata traffic to the IdP.
    /// A <see langword="null"/> result must leave previously cached metadata intact.
    /// </remarks>
    Task<OpenIdConnectConfiguration?> RefreshConfigurationAsync(string authority, CancellationToken cancellationToken = default);
}
