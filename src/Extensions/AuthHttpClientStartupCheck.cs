using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Extensions;

/// <summary>
/// Fails fast at startup if the named <see cref="HttpClient"/> used by the
/// auth-flow services (refresh, exchange, revocation, discovery) is not
/// registered.
///
/// Without this check, a typo or accidental rename of
/// <see cref="AuthenticationServiceExtensions.TokenHttpClientName"/> causes
/// <see cref="IHttpClientFactory.CreateClient(string)"/> to silently return
/// the default, unconfigured client - losing the standard resilience handler
/// (timeout, retry, circuit breaker) and exposing every auth path to OS-level
/// socket hangs against a slow IdP.
/// </summary>
internal sealed class AuthHttpClientStartupCheck(
    ILogger<AuthHttpClientStartupCheck> logger,
    IOptionsMonitor<HttpClientFactoryOptions> httpClientOptions) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var name = AuthenticationServiceExtensions.TokenHttpClientName;
        var options = httpClientOptions.Get(name);

        // An unregistered name resolves to an options instance with no client
        // actions configured - the factory will hand back the default client.
        if (options.HttpClientActions.Count == 0)
        {
            logger.AuthHttpClientMissing(name);
            throw new InvalidOperationException(
                $"Porta: the named HttpClient \"{name}\" is not registered. " +
                "Auth-flow services (TokenRefreshService, TokenExchangeService, " +
                "TokenRevocationService, DiscoveryService) resolve this client by " +
                "name to inherit the standard resilience handler (timeout, retry, " +
                "circuit breaker). A missing registration silently downgrades them " +
                "to the default unconfigured client and can hang auth paths against " +
                "a slow IdP. Ensure AddPortaAuthentication is called (it registers " +
                $"\"{name}\" in AddTokenServices).");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

internal static partial class AuthHttpClientStartupCheckLogging
{
    [LoggerMessage(EventId = 14600, Level = LogLevel.Critical,
        Message = "Porta: the named HttpClient \"{HttpClientName}\" is not registered. " +
                  "Refusing to start - auth-flow services would silently fall back to " +
                  "the default unconfigured client and lose the resilience pipeline.")]
    public static partial void AuthHttpClientMissing(this ILogger logger, string httpClientName);
}
