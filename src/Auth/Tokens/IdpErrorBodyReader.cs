using b17s.Porta.Configuration;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Drops or truncates raw IdP error response bodies before they reach log sinks or
/// failure-result strings. Verbose IdPs (Keycloak, IdentityServer in dev mode) echo
/// the submitted refresh token, client secret, or PII back inside the error JSON;
/// embedding those bytes into a failure string would smuggle them into structured
/// logs and exception telemetry.
/// </summary>
internal static class IdpErrorBodyReader
{
    /// <summary>
    /// Reads the body when <see cref="PortaCoreOptions.LogIdpErrorBodies"/> is true,
    /// truncated to <see cref="PortaCoreOptions.IdpErrorBodyMaxBytes"/>. Otherwise
    /// returns <c>"(redacted)"</c> and does not touch the body.
    /// </summary>
    public static async Task<string> ReadSafeAsync(
        HttpResponseMessage response,
        PortaCoreOptions coreOptions,
        CancellationToken cancellationToken = default)
    {
        if (!coreOptions.LogIdpErrorBodies)
        {
            return "(redacted)";
        }

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        var max = Math.Max(0, coreOptions.IdpErrorBodyMaxBytes);
        if (content.Length <= max)
        {
            return content;
        }
        return content[..max] + "…(truncated)";
    }
}
