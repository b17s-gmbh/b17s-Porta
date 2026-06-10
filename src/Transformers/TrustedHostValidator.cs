using System.Text.RegularExpressions;

using b17s.Porta.Configuration;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Transformers;

/// <summary>
/// Validates backend URLs against trusted hosts for user token forwarding.
/// Performs validation at startup time only - no runtime overhead.
/// </summary>
public interface ITrustedHostValidator
{
    /// <summary>
    /// Validates that a URL is in the trusted hosts list.
    /// Call this at startup when configuring endpoints with WithUserToken().
    /// </summary>
    /// <param name="url">The backend URL to validate</param>
    /// <param name="endpointName">The endpoint name (for error messages)</param>
    /// <exception cref="InvalidOperationException">Thrown if URL is not trusted</exception>
    void ValidateUrl(string url, string endpointName);

    /// <summary>
    /// Checks if a URL is trusted without throwing.
    /// </summary>
    bool IsTrusted(string url);
}

/// <summary>
/// Default implementation of trusted host validation.
/// Compiles patterns at construction time for efficient matching.
/// </summary>
public sealed class TrustedHostValidator : ITrustedHostValidator
{
    private readonly List<Regex> _trustedPatterns = [];
    private readonly List<string> _trustedHosts = [];
    private readonly ILogger<TrustedHostValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustedHostValidator"/> class, compiling the
    /// configured <see cref="PortaCoreOptions.TrustedHosts"/> patterns into regular expressions for
    /// efficient matching at validation time.
    /// </summary>
    /// <param name="options">Porta core options supplying the trusted-host allow-list.</param>
    /// <param name="logger">Logger for diagnostic and audit messages.</param>
    public TrustedHostValidator(
        IOptions<PortaCoreOptions> options,
        ILogger<TrustedHostValidator> logger)
    {
        _logger = logger;
        _trustedHosts = options.Value.TrustedHosts;

        foreach (var host in _trustedHosts)
        {
            var pattern = ConvertToRegex(host);
            _trustedPatterns.Add(pattern);
            _logger.RegisteredTrustedHostPattern(host, pattern);
        }

        if (_trustedPatterns.Count > 0)
        {
            _logger.TrustedHostValidationEnabled(_trustedPatterns.Count);
        }
    }

    /// <inheritdoc/>
    public void ValidateUrl(string url, string endpointName)
    {
        if (_trustedPatterns.Count == 0)
        {
            throw new InvalidOperationException(
                $"Backend endpoint '{endpointName}' uses WithUserToken() but no trusted hosts are configured. " +
                $"Configure PortaCore:TrustedHosts in appsettings.json or call " +
                $"services.Configure<PortaCoreOptions>(o => o.TrustedHosts.Add(\"{TryGetAuthority(url) ?? url}\"))");
        }

        if (HasPlaceholderInAuthority(url))
        {
            throw new InvalidOperationException(
                $"Backend endpoint '{endpointName}' URL '{url}' contains a '{{...}}' placeholder in the scheme, host, or port. " +
                $"WithUserToken() forwards the user's OAuth token, so the destination authority must be a literal value " +
                $"that can be checked against PortaCore:TrustedHosts at startup. " +
                $"Move the placeholder into the path, or hard-code the host.");
        }

        if (!IsTrusted(url))
        {
            throw new InvalidOperationException(
                $"Backend endpoint '{endpointName}' URL '{url}' is not in the trusted hosts list. " +
                $"WithUserToken() forwards the user's OAuth token and should only be used with trusted internal services. " +
                $"Add the host to PortaCore:TrustedHosts or use a different auth policy. " +
                $"Configured trusted hosts: [{string.Join(", ", _trustedHosts)}]");
        }

        _logger.ValidatedTrustedHost(endpointName, url);
    }

    /// <inheritdoc/>
    public bool IsTrusted(string url)
    {
        if (_trustedPatterns.Count == 0)
        {
            return false;
        }

        var host = TryGetAuthority(url);
        return host is not null && _trustedPatterns.Any(p => p.IsMatch(host));
    }

    private static string? TryGetAuthority(string url)
    {
        try
        {
            var uri = new Uri(url);
            // Canonical scheme + host + port (userinfo excluded, default ports normalized).
            return uri.GetLeftPart(UriPartial.Authority);
        }
        catch (UriFormatException)
        {
            // If the URL doesn't parse, we cannot safely compare it against the trusted-host
            // patterns. Reject (fail closed) rather than reconstructing the authority by hand:
            // naive string-slicing diverges from Uri canonicalization - for example it would
            // treat the userinfo in `https://trusted.example.com@evil.com` as the host instead
            // of `evil.com`. Authority-placeholder templates are already rejected up front by
            // HasPlaceholderInAuthority before validation reaches here.
            return null;
        }
    }

    // Reject `{...}` placeholders inside the scheme, host, or port. RouteUrlInterpolator
    // forbids interpolation that changes the authority at request time, but only if the
    // template's authority parsed cleanly to begin with. A template like
    // `http://{host}/api` would otherwise sail through startup validation against the
    // literal substring `{host}`.
    // The authority ends at the first '/', '?' or '#': a path-less URL can still carry a
    // query or fragment (`https://api.example.com?x={y}`), whose placeholders are fine.
    private static readonly char[] AuthorityEndDelimiters = ['/', '?', '#'];

    private static bool HasPlaceholderInAuthority(string url)
    {
        var schemeEnd = url.IndexOf("://", StringComparison.Ordinal);
        var authorityStart = schemeEnd < 0 ? 0 : schemeEnd + 3;
        var authorityEnd = url.IndexOfAny(AuthorityEndDelimiters, authorityStart);
        if (authorityEnd < 0) authorityEnd = url.Length;

        var prefix = url[..authorityEnd];
        return prefix.Contains('{') || prefix.Contains('}');
    }

    private static Regex ConvertToRegex(string pattern)
    {
        // Normalize: ensure scheme is present
        if (!pattern.Contains("://"))
        {
            pattern = "https://" + pattern;
        }

        // Escape regex special characters except *
        var escaped = Regex.Escape(pattern);

        // Convert wildcards: *.example.com -> [^./]+\.example\.com
        // Use [^./]+ (not [^/]+) so * matches a single subdomain label only.
        // Otherwise *.example.com would match attacker.evil.example.com.
        escaped = escaped.Replace("\\*", "[^./]+");

        // Anchor the pattern
        return new Regex($"^{escaped}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    }
}

// EventId range 14030-14039 is reserved for this category (14100+ belongs to
// the token services) so EventId-based filtering can tell them apart.
internal static partial class TrustedHostValidatorLogging
{
    [LoggerMessage(EventId = 14030, Level = LogLevel.Debug,
        Message = "Registered trusted host pattern: {Host} -> {Pattern}")]
    public static partial void RegisteredTrustedHostPattern(this ILogger<TrustedHostValidator> logger, string host, Regex pattern);

    [LoggerMessage(EventId = 14031, Level = LogLevel.Information,
        Message = "Trusted host validation enabled with {Count} patterns")]
    public static partial void TrustedHostValidationEnabled(this ILogger<TrustedHostValidator> logger, int count);

    [LoggerMessage(EventId = 14032, Level = LogLevel.Debug,
        Message = "Validated trusted host for endpoint '{Endpoint}': {Url}")]
    public static partial void ValidatedTrustedHost(this ILogger<TrustedHostValidator> logger, string endpoint, string url);
}
