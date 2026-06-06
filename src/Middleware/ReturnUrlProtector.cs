using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;

namespace b17s.Porta.Middleware;

/// <summary>
/// Issues and verifies short-lived, signed return-URL tokens used by the OIDC
/// login endpoint. The wrapped value is opaque to callers - they cannot pre-set
/// arbitrary post-login destinations without a server-issued token.
/// </summary>
public interface IReturnUrlProtector
{
    string Protect(string returnUrl, TimeSpan lifetime);

    bool TryUnprotect(string token, out string returnUrl);
}

internal sealed class ReturnUrlProtector : IReturnUrlProtector
{
    internal const string Purpose = "b17s.Porta.OidcLogin.ReturnUrl.v1";

    private readonly ITimeLimitedDataProtector _protector;
    private readonly ILogger<ReturnUrlProtector> _logger;

    public ReturnUrlProtector(IDataProtectionProvider provider, ILogger<ReturnUrlProtector> logger)
    {
        _protector = provider.CreateProtector(Purpose).ToTimeLimitedDataProtector();
        _logger = logger;
    }

    public string Protect(string returnUrl, TimeSpan lifetime)
    {
        ArgumentException.ThrowIfNullOrEmpty(returnUrl);
        return _protector.Protect(returnUrl, lifetime);
    }

    public bool TryUnprotect(string token, out string returnUrl)
    {
        returnUrl = string.Empty;
        if (string.IsNullOrEmpty(token))
            return false;

        try
        {
            returnUrl = _protector.Unprotect(token);
            return !string.IsNullOrEmpty(returnUrl);
        }
        catch (Exception ex)
        {
            _logger.ReturnUrlUnprotectFailed(ex);
            return false;
        }
    }
}

internal static partial class ReturnUrlProtectorLogging
{
    [LoggerMessage(EventId = 9800, Level = LogLevel.Trace,
        Message = "Failed to unprotect return-url token (expired, tampered, or wrong key)")]
    public static partial void ReturnUrlUnprotectFailed(this ILogger logger, Exception ex);
}
