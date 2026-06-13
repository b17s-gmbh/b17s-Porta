using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Extensions;

/// <summary>
/// Fails fast at startup when <see cref="BackendServiceOptions"/> declares token-exchange intent
/// (a <see cref="BackendServiceOptions.DefaultTokenExchangeAudience"/> or any
/// <see cref="BackendServiceOptions.TokenExchangeAudiences"/> entry) but <see cref="IApiTokenService"/>
/// is not registered - i.e. <c>AddPortaAuthentication()</c> / <c>AddPortaOidcAuth()</c> was not called.
/// <para>
/// Without this check the misconfiguration only surfaces when the first request hits a token-exchange
/// route, where it is mapped to <see cref="b17s.Porta.Transformers.BackendErrorType.ConfigurationError"/> at request time.
/// Catching it at startup turns a confusing per-request failure into a clear boot error.
/// </para>
/// <para>
/// Bounded by design: it can only see audiences declared through <see cref="BackendServiceOptions"/>.
/// An endpoint that supplies its audience inline via <c>WithTokenExchange(audience)</c> without any
/// options-level audience is invisible here and still relies on the request-time guard.
/// </para>
/// </summary>
internal sealed class TokenExchangeConfigurationStartupCheck(
    ILogger<TokenExchangeConfigurationStartupCheck> logger,
    IOptions<BackendServiceOptions> backendOptions,
    IServiceProviderIsService serviceProviderIsService) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var options = backendOptions.Value;
        var declaresTokenExchange =
            !string.IsNullOrEmpty(options.DefaultTokenExchangeAudience)
            || options.TokenExchangeAudiences.Count > 0;

        if (declaresTokenExchange && !serviceProviderIsService.IsService(typeof(IApiTokenService)))
        {
            logger.TokenExchangeServiceMissing();
            throw new InvalidOperationException(
                "Porta: token-exchange audiences are configured in BackendServiceOptions " +
                "(DefaultTokenExchangeAudience or TokenExchangeAudiences) but IApiTokenService is not " +
                "registered. Token exchange would fail at request time. Call AddPortaAuthentication() " +
                "or AddPortaOidcAuth() to register the token-exchange dependencies.");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

internal static partial class TokenExchangeConfigurationStartupCheckLogging
{
    [LoggerMessage(EventId = 14610, Level = LogLevel.Critical,
        Message = "Porta: token-exchange audiences are configured but IApiTokenService is not registered. " +
                  "Refusing to start - call AddPortaAuthentication() or AddPortaOidcAuth().")]
    public static partial void TokenExchangeServiceMissing(this ILogger logger);
}
