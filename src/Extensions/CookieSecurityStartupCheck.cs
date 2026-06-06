using b17s.Porta.Configuration;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Extensions;

/// <summary>
/// Fails fast (outside Development) when the BFF auth pipeline is wired with a
/// transport-security downgrade that would expose the session cookie or OIDC
/// metadata over plaintext HTTP:
/// <list type="bullet">
///   <item><see cref="CookieSecurityConfiguration.SecurePolicy"/> is not
///   <c>Always</c> - the auth cookie may then be emitted without the
///   <c>Secure</c> attribute and leak over HTTP.</item>
///   <item><see cref="SessionAuthenticationConfiguration.RequireHttpsMetadata"/>
///   is <c>false</c> - OIDC discovery/metadata (and the handler's authority)
///   may be fetched over plaintext HTTP, opening a man-in-the-middle window.</item>
/// </list>
/// The shipped defaults are secure (<c>SecurePolicy=Always</c>,
/// <c>RequireHttpsMetadata=true</c>) and bad enum values are already rejected by
/// <see cref="SessionAuthenticationConfigurationValidator"/>; this guard catches the
/// case where an operator deliberately loosens a default. It warns instead of
/// throwing in Development so local loops against a non-HTTPS IdP keep working,
/// mirroring <see cref="HaConfigurationStartupCheck"/> and the OIDC startup checks.
/// </summary>
internal sealed class CookieSecurityStartupCheck(
    ILogger<CookieSecurityStartupCheck> logger,
    IHostEnvironment environment,
    IOptions<SessionAuthenticationConfiguration> options) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var config = options.Value;
        var isDevelopment = environment.IsDevelopment();

        // SecurePolicy != Always means the Secure attribute is conditional (SameAsRequest)
        // or omitted (None). Either way the cookie can travel over plaintext HTTP. The
        // value itself is already validated to be one of Always/SameAsRequest/None.
        var securePolicy = config.Cookie.SecurePolicy;
        if (!string.Equals(securePolicy, "Always", StringComparison.Ordinal))
        {
            if (isDevelopment)
            {
                logger.CookieSecurePolicyDowngradeDevelopment(securePolicy);
            }
            else
            {
                logger.CookieSecurePolicyDowngradeFatal(securePolicy);
                throw new InvalidOperationException(
                    $"Porta: SessionAuthentication.Cookie.SecurePolicy is '{securePolicy}' outside a " +
                    "Development environment. The session cookie carries the opaque auth ticket; with " +
                    "SecurePolicy other than 'Always' it can be emitted without the Secure attribute and " +
                    "leak over plaintext HTTP. Set SecurePolicy='Always' (the default). If you terminate " +
                    "TLS at a reverse proxy, keep 'Always' - it marks the cookie Secure regardless of the " +
                    "scheme the app sees. This downgrade is only permitted in Development.");
            }
        }

        // RequireHttpsMetadata=false lets the OIDC handler fetch discovery/metadata - and
        // accept an authority - over plaintext HTTP, which a network attacker can tamper with.
        if (!config.RequireHttpsMetadata)
        {
            if (isDevelopment)
            {
                logger.RequireHttpsMetadataDisabledDevelopment();
            }
            else
            {
                logger.RequireHttpsMetadataDisabledFatal();
                throw new InvalidOperationException(
                    "Porta: SessionAuthentication.RequireHttpsMetadata is false outside a Development " +
                    "environment. OIDC discovery/metadata (and the handler's authority) would be reachable " +
                    "over plaintext HTTP, allowing a man-in-the-middle to tamper with signing keys and " +
                    "endpoints. Set RequireHttpsMetadata=true (the default). This downgrade is only " +
                    "permitted in Development against a non-HTTPS IdP.");
            }
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

internal static partial class CookieSecurityStartupCheckLogging
{
    [LoggerMessage(EventId = 14700, Level = LogLevel.Warning,
        Message = "Porta: SessionAuthentication.Cookie.SecurePolicy is '{SecurePolicy}'. This is " +
                  "permitted in Development; in non-Development it would be a startup failure. The " +
                  "session cookie can then be emitted without the Secure attribute and leak over " +
                  "plaintext HTTP. Set SecurePolicy='Always' before deploying.")]
    public static partial void CookieSecurePolicyDowngradeDevelopment(this ILogger logger, string securePolicy);

    [LoggerMessage(EventId = 14701, Level = LogLevel.Critical,
        Message = "Porta: SessionAuthentication.Cookie.SecurePolicy is '{SecurePolicy}' outside " +
                  "Development. Refusing to start - the session cookie could be emitted without the " +
                  "Secure attribute and leak over plaintext HTTP. Set SecurePolicy='Always'.")]
    public static partial void CookieSecurePolicyDowngradeFatal(this ILogger logger, string securePolicy);

    [LoggerMessage(EventId = 14702, Level = LogLevel.Warning,
        Message = "Porta: SessionAuthentication.RequireHttpsMetadata is false. This is permitted in " +
                  "Development; in non-Development it would be a startup failure. OIDC discovery/metadata " +
                  "would be reachable over plaintext HTTP and tamperable by a man-in-the-middle. Set " +
                  "RequireHttpsMetadata=true before deploying.")]
    public static partial void RequireHttpsMetadataDisabledDevelopment(this ILogger logger);

    [LoggerMessage(EventId = 14703, Level = LogLevel.Critical,
        Message = "Porta: SessionAuthentication.RequireHttpsMetadata is false outside Development. " +
                  "Refusing to start - OIDC discovery/metadata would be reachable over plaintext HTTP " +
                  "and tamperable by a man-in-the-middle. Set RequireHttpsMetadata=true.")]
    public static partial void RequireHttpsMetadataDisabledFatal(this ILogger logger);
}
