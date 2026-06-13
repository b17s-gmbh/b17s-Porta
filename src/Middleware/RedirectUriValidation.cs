using System.Globalization;
using System.Net;

namespace b17s.Porta.Middleware;

internal static class RedirectUriValidation
{
    private static readonly IdnMapping s_idn = new();

    /// <summary>
    /// Strips the query string and fragment from a redirect URI before it is
    /// logged. Externally-supplied redirect URIs can carry secrets in the query
    /// (e.g. <c>?access_token=…</c>), and Porta's log stream is Secret-classified,
    /// so only scheme+host+path (or the path portion of a relative URI) may be
    /// emitted. Falls back to naive separator-slicing when the value does not
    /// parse as an absolute URI (relative paths, malformed input).
    /// </summary>
    public static string StripQueryForLogging(string uri)
    {
        if (string.IsNullOrEmpty(uri))
            return uri;

        // Only treat values with an explicit scheme as absolute. A leading '/'
        // is a relative redirect path, but Uri.TryCreate(Absolute) parses it as a
        // 'file://' URI on Unix - that would mangle the logged value - so route
        // relative/malformed input through plain separator-slicing instead.
        if (!uri.StartsWith('/') && Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
            return parsed.GetLeftPart(UriPartial.Path);

        var queryIndex = uri.IndexOf('?');
        var fragmentIndex = uri.IndexOf('#');
        var cut = queryIndex >= 0 && fragmentIndex >= 0
            ? Math.Min(queryIndex, fragmentIndex)
            : Math.Max(queryIndex, fragmentIndex);
        return cut >= 0 ? uri[..cut] : uri;
    }

    public static bool IsSafeRelativeUri(string uri)
    {
        if (!uri.StartsWith('/')
            || uri.StartsWith("//", StringComparison.Ordinal)
            || uri.StartsWith("/\\", StringComparison.Ordinal))
        {
            return false;
        }

        // Defense-in-depth: a percent-encoded separator in the leading position
        // (`/%2F…`, `/%5C…`) decodes to a protocol-relative external origin
        // (`//host` / `/\host`) once unescaped downstream. No concrete browser
        // bypass is known at origin resolution, but normalize once and re-check
        // so the guarantee does not depend on who decodes the value. (Pathological
        // double-encoding `/%252F…` is out of scope — it requires two decode passes.)
        var decoded = Uri.UnescapeDataString(uri);
        return !decoded.StartsWith("//", StringComparison.Ordinal)
            && !decoded.StartsWith("/\\", StringComparison.Ordinal);
    }

    public static bool IsLocalhost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            return true;

        var candidate = host;
        if (candidate.Length >= 2 && candidate[0] == '[' && candidate[^1] == ']')
            candidate = candidate[1..^1];

        var zoneIndex = candidate.IndexOf('%');
        if (zoneIndex >= 0)
            candidate = candidate[..zoneIndex];

        return IPAddress.TryParse(candidate, out var address) && IPAddress.IsLoopback(address);
    }

    /// <summary>
    /// Normalizes a hostname for comparison: strips trailing dot, lowercases,
    /// and converts unicode/IDN hostnames to their punycode form so that
    /// "müller.example" and "xn--mller-kva.example" compare equal.
    /// </summary>
    public static string NormalizeHost(string host)
    {
        if (string.IsNullOrEmpty(host))
            return string.Empty;

        var trimmed = host.TrimEnd('.');
        // Bracketed IPv6 literal - leave as-is, just lowercase.
        if (trimmed.Length >= 2 && trimmed[0] == '[' && trimmed[^1] == ']')
            return trimmed.ToLowerInvariant();

        // IPAddress hosts: lowercase suffices (they're already ASCII).
        if (IPAddress.TryParse(trimmed, out _))
            return trimmed.ToLowerInvariant();

        try
        {
            return s_idn.GetAscii(trimmed).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            // Not a valid IDN domain - fall back to lowercase compare.
            return trimmed.ToLowerInvariant();
        }
    }

    /// <summary>
    /// Returns true when <paramref name="parsed"/>'s host (and port, when the
    /// allow-list entry specifies one) matches any entry in <paramref name="allowedHosts"/>.
    /// An entry of <c>"app.example.com"</c> matches any port; an entry of
    /// <c>"app.example.com:8443"</c> pins the port. Comparison is case-insensitive
    /// and IDN-aware.
    /// </summary>
    public static bool MatchesAllowedHost(Uri parsed, IReadOnlyCollection<string> allowedHosts)
    {
        if (allowedHosts.Count == 0)
            return false;

        var requestHost = NormalizeHost(parsed.Host);
        var requestPort = parsed.IsDefaultPort ? -1 : parsed.Port;

        foreach (var entry in allowedHosts)
        {
            if (string.IsNullOrEmpty(entry))
                continue;

            var (allowedHost, allowedPort) = SplitHostPort(entry);
            var normalizedAllowedHost = NormalizeHost(allowedHost);
            if (!string.Equals(normalizedAllowedHost, requestHost, StringComparison.Ordinal))
                continue;

            // No port specified in the allow-list entry → any port matches.
            if (allowedPort is null)
                return true;

            if (allowedPort.Value == requestPort)
                return true;
        }

        return false;
    }

    private static (string Host, int? Port) SplitHostPort(string entry)
    {
        // IPv6 literal: [::1]:8443 or [::1]
        if (entry.StartsWith('['))
        {
            var close = entry.IndexOf(']');
            if (close < 0)
                return (entry, null);

            var host = entry[..(close + 1)];
            if (close + 1 < entry.Length && entry[close + 1] == ':' && int.TryParse(
                entry.AsSpan(close + 2), NumberStyles.None, CultureInfo.InvariantCulture, out var port))
            {
                return (host, port);
            }
            return (host, null);
        }

        var colon = entry.LastIndexOf(':');
        // Bare IPv6 without brackets has many colons - treat as host-only.
        if (colon < 0 || entry.IndexOf(':') != colon)
            return (entry, null);

        if (int.TryParse(entry.AsSpan(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var p))
        {
            return (entry[..colon], p);
        }
        return (entry, null);
    }

    /// <summary>
    /// Validates a configured default redirect URI at startup. Returns null on
    /// success or a human-readable failure reason. The runtime guard cannot save
    /// us here: the default is the fallback used when no caller-supplied URI is
    /// validated, so a misconfigured absolute URI would silently exfiltrate
    /// users to an attacker-controlled host.
    /// </summary>
    public static string? ValidateConfiguredRedirectUri(string? uri, IReadOnlyCollection<string> allowedHosts, bool allowLocalhost)
    {
        if (string.IsNullOrEmpty(uri))
            return "must not be empty";

        if (uri.StartsWith('/'))
        {
            return IsSafeRelativeUri(uri)
                ? null
                : "relative URI must not be protocol-relative ('//host') or backslash-prefixed ('/\\host')";
        }

        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
            return $"'{uri}' is not a valid absolute URI or safe relative path (must start with '/')";

        if (parsed.Scheme != "https" && !(allowLocalhost && IsLocalhost(parsed.Host)))
            return $"absolute URI '{uri}' must use https (or be localhost when AllowLocalhost=true)";

        if (allowLocalhost && IsLocalhost(parsed.Host))
            return null;

        if (allowedHosts.Count == 0)
            return $"absolute URI host '{parsed.Host}' is not allowed: AllowedRedirectHosts is empty, so only same-origin/relative URIs are accepted (set AllowLocalhost=true to permit loopback)";

        return MatchesAllowedHost(parsed, allowedHosts)
            ? null
            : $"absolute URI host '{parsed.Host}' (port {(parsed.IsDefaultPort ? "default" : parsed.Port.ToString(CultureInfo.InvariantCulture))}) is not in AllowedRedirectHosts";
    }
}
