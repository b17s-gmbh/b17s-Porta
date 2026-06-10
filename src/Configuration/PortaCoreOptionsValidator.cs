using Microsoft.Extensions.Options;

namespace b17s.Porta.Configuration;

/// <summary>
/// Validates <see cref="PortaCoreOptions"/> at startup so a misconfigured BFF fails
/// on boot instead of at the first backend call, where the error surfaces as an
/// <see cref="ArgumentOutOfRangeException"/> from deep inside <see cref="HttpClient"/>
/// creation or the resilience pipeline.
///
/// Wired in <see cref="b17s.Porta.Extensions.PortaServiceExtensions"/> via
/// <c>AddPortaCore</c> together with <c>ValidateOnStart()</c>, mirroring the
/// fail-at-boot posture of <see cref="SessionAuthenticationConfigurationValidator"/>.
/// </summary>
internal sealed class PortaCoreOptionsValidator : IValidateOptions<PortaCoreOptions>
{
    /// <summary>
    /// Ceiling for <see cref="PortaCoreOptions.IdpErrorBodyMaxBytes"/> (1 MiB). The value is a
    /// log-truncation cap for IdP error bodies, so anything above this is unequivocally a
    /// misconfiguration - and an unbounded value overflows the <c>max + 1</c> read buffer in
    /// <see cref="b17s.Porta.Auth.Tokens.IdpErrorBodyReader"/> at <see cref="int.MaxValue"/>.
    /// </summary>
    internal const int IdpErrorBodyMaxBytesCeiling = 1024 * 1024;

    public ValidateOptionsResult Validate(string? name, PortaCoreOptions options)
    {
        var errors = new List<string>();

        // HttpClient.Timeout rejects non-positive values at client creation, and the
        // resilience pipeline derives its attempt/total timeouts from this value -
        // both would otherwise throw on the first backend call.
        if (options.DefaultTimeout <= TimeSpan.Zero)
        {
            errors.Add(
                $"PortaCore.DefaultTimeout must be > 0. Got: {options.DefaultTimeout}.");
        }

        // A negative skew would treat expired tokens as live past their exp.
        if (options.TokenRefreshSkew < TimeSpan.Zero)
        {
            errors.Add(
                $"PortaCore.TokenRefreshSkew must be >= 0. Got: {options.TokenRefreshSkew}.");
        }

        // -1 (unlimited) and 0 (no body logs) are documented special values.
        if (options.MaxBodyLogLength < -1)
        {
            errors.Add(
                $"PortaCore.MaxBodyLogLength must be >= -1 (-1 = unlimited, 0 = no body logs). " +
                $"Got: {options.MaxBodyLogLength}.");
        }

        if (options.IdpErrorBodyMaxBytes < 0 || options.IdpErrorBodyMaxBytes > IdpErrorBodyMaxBytesCeiling)
        {
            errors.Add(
                $"PortaCore.IdpErrorBodyMaxBytes must be between 0 and {IdpErrorBodyMaxBytesCeiling} " +
                $"(1 MiB). Got: {options.IdpErrorBodyMaxBytes}. The value is a log-truncation cap " +
                "for IdP error bodies, not a streaming limit.");
        }

        // Intentionally NOT validated:
        // - MaxRetryAttempts: a value below 1 is the documented way to disable retries
        //   app-wide; ConfigureBackendResilience models it as a never-retry predicate
        //   instead of handing the invalid count to Polly.
        // - MaxBackendResponseBytes / MaxRawForwardResponseBytes /
        //   RawForwardReadIdleTimeout: non-positive values are the documented way to
        //   disable the respective cap.

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }
}
