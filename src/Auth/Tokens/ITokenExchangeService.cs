using b17s.Porta.Configuration;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Provides OAuth token exchange functionality for API-specific tokens
/// </summary>
public interface ITokenExchangeService
{
    /// <summary>
    /// Exchanges an access token for an API-specific token
    /// </summary>
    /// <param name="accessToken">The current access token</param>
    /// <param name="apiConfig">Configuration for the target API</param>
    /// <param name="cancellationToken">Cancellation token tied to the inbound request lifetime</param>
    /// <returns>Token exchange result with success/failure status</returns>
    Task<TokenExchangeResult> ExchangeAsync(string accessToken, ApiConfiguration apiConfig, CancellationToken cancellationToken = default);
}
