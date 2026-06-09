using System.Text;

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
    /// truncated to <see cref="PortaCoreOptions.IdpErrorBodyMaxBytes"/> bytes. Otherwise
    /// returns <c>"(redacted)"</c> and does not touch the body.
    /// </summary>
    /// <remarks>
    /// The cap is enforced in <em>bytes</em>, not characters: at most
    /// <see cref="PortaCoreOptions.IdpErrorBodyMaxBytes"/> bytes are pulled off the response
    /// stream, so a hostile or oversized body is never buffered in full. The capped bytes are
    /// decoded as UTF-8 (the OAuth/OIDC error wire format); a byte-boundary cut that splits a
    /// trailing multi-byte sequence is rendered as a Unicode replacement character rather than
    /// throwing.
    /// </remarks>
    public static async Task<string> ReadSafeAsync(
        HttpResponseMessage response,
        PortaCoreOptions coreOptions,
        CancellationToken cancellationToken = default)
    {
        if (!coreOptions.LogIdpErrorBodies)
        {
            return "(redacted)";
        }

        var max = Math.Max(0, coreOptions.IdpErrorBodyMaxBytes);

        // Read at most max+1 bytes off the stream: the extra byte reveals whether the body
        // overran the cap without materializing the whole (possibly huge) response in memory.
        var buffer = new byte[max + 1];
        var total = 0;

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken);
            if (read == 0)
            {
                break;
            }
            total += read;
        }

        var truncated = total > max;
        var byteCount = truncated ? max : total;

        // Encoding.UTF8 decodes with a replacement fallback, so a multi-byte sequence severed
        // by the byte cap yields U+FFFD instead of throwing.
        var text = Encoding.UTF8.GetString(buffer, 0, byteCount);

        return truncated ? text + "…(truncated)" : text;
    }
}
