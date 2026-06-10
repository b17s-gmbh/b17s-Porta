namespace b17s.Porta.Transformers;

/// <summary>
/// Replaces <c>{name}</c> placeholders in a URL template with values from a
/// route-values dictionary. Used by every endpoint builder + raw-forward path
/// where a configured backend URL contains route parameters that need to be
/// filled in from the incoming request.
/// </summary>
/// <remarks>
/// A single-segment placeholder (<c>{name}</c>) substitutes a value encoded as one
/// path segment with <see cref="Uri.EscapeDataString(string)"/> so an attacker who
/// controls a route value cannot break out of the segment: a raw <c>/</c> becomes
/// <c>%2F</c> (no new path segment), and <c>@</c>/<c>:</c> can no longer act as
/// authority delimiters.
/// A catch-all placeholder (<c>{*name}</c> or <c>{**name}</c>) is the explicit opt-in
/// for subtree proxying: the value's <c>/</c> separators are preserved so a nested
/// request path forwards to a nested backend path, while every individual segment is
/// still <see cref="Uri.EscapeDataString(string)"/>-encoded (so <c>@</c>/<c>:</c> within
/// a segment still cannot pivot the authority). The relaxation is keyed off the
/// catch-all syntax in the backend template, not inferred, so a plain <c>{name}</c>
/// stays locked down by default.
/// In both modes, values containing a <c>.</c>/<c>..</c> traversal component, a literal
/// <c>?</c>/<c>#</c>/<c>\</c>, or an already-encoded separator (<c>%2F</c>, <c>%5C</c>,
/// <c>%2E</c>) are rejected outright, the latter because <see cref="Uri"/> canonicalization
/// would collapse them on resolution.
/// After substitution, the result is parsed back to a <see cref="Uri"/> and the
/// host + path prefix are compared against the static portion of the template
/// to defeat any encoding bypass we missed.
/// </remarks>
internal static class RouteUrlInterpolator
{
    public static string Interpolate(string urlTemplate, IEnumerable<KeyValuePair<string, object?>> routeValues)
    {
        var url = urlTemplate;
        foreach (var (key, value) in routeValues)
        {
            var raw = value?.ToString();

            // ASP.NET Core route binding stores both `{*path}` and `{**path}` under the bare
            // parameter name ("path"), so we accept either catch-all syntax in the backend
            // template and treat it as the subtree-proxy opt-in. The bare `{path}` form stays
            // single-segment (slashes encoded). Catch-all forms are checked first because the
            // bare form would not match them anyway, and we want their slash-preserving encoding.
            //
            // Case-insensitive, matching routing semantics: RouteValueDictionary keys are
            // OrdinalIgnoreCase, so routing itself cannot keep `{Id}` and `{id}` distinct - a
            // case-sensitive replace here would just leave a casing mismatch between the route
            // pattern and the backend template as a literal `{Id}` forwarded to the backend.
            url = ReplacePlaceholder(url, $"{{**{key}}}", raw, catchAll: true);
            url = ReplacePlaceholder(url, $"{{*{key}}}", raw, catchAll: true);
            url = ReplacePlaceholder(url, $"{{{key}}}", raw, catchAll: false);
        }

        EnsureWithinTemplateBoundary(urlTemplate, url);
        return url;
    }

    /// <summary>
    /// Merges an inbound query string into an already-interpolated backend URL so typed
    /// pass-through/transformer endpoints forward <c>?filter</c>, <c>?page</c>, etc. to the
    /// backend exactly as the raw-forward path does.
    /// </summary>
    /// <param name="url">The interpolated backend URL (the static template may itself carry a query).</param>
    /// <param name="inboundQueryString">
    /// The incoming request's query string, expected in <see cref="Microsoft.AspNetCore.Http.QueryString"/>
    /// form (leading <c>?</c> included). Null or empty leaves <paramref name="url"/> untouched.
    /// </param>
    /// <returns>
    /// <paramref name="url"/> with the inbound query appended: with <c>&amp;</c> when the URL already
    /// carries a query (so a second <c>?</c> is never emitted), otherwise with the leading <c>?</c> intact.
    /// </returns>
    public static string AppendQueryString(string url, string? inboundQueryString)
    {
        if (string.IsNullOrEmpty(inboundQueryString))
        {
            return url;
        }

        // inboundQueryString includes the leading '?'. If the backend template already carries a
        // query string, merge with '&' so we don't emit a second '?' (which yields a malformed URL
        // and swallows the inbound params).
        return url + (url.Contains('?', StringComparison.Ordinal)
            ? string.Concat("&", inboundQueryString.AsSpan(1))
            : inboundQueryString);
    }

    private static string ReplacePlaceholder(string url, string placeholder, string? value, bool catchAll)
    {
        if (!url.Contains(placeholder, StringComparison.OrdinalIgnoreCase))
        {
            return url;
        }

        var encoded = EncodeRouteValue(value, catchAll);
        return url.Replace(placeholder, encoded, StringComparison.OrdinalIgnoreCase);
    }

    private static string EncodeRouteValue(string? value, bool catchAll)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        // Reject path/query/fragment-smuggling characters. ASP.NET Core route
        // binding leaves these intact when a value is bound to a single segment
        // (`{id}`) and especially to a catch-all (`{**path}`).
        if (value.Contains('?') || value.Contains('#') || value.Contains('\\'))
        {
            throw new InvalidRouteValueException("Route value contains '?', '#', or '\\' which would smuggle into the backend URL.");
        }

        // %2F / %5C decode to '/' and '\' after Uri canonicalization. %2E decodes to '.' -
        // by itself harmless, but combined with a literal dot it forms a traversal segment
        // (e.g. ".%2E/" canonicalizes to "../"). Rejecting any encoded dot/slash/backslash
        // in route values keeps the segment-level check below sound.
        if (value.Contains("%2F", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("%5C", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("%2E", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidRouteValueException("Route value contains an encoded path separator or traversal sequence.");
        }

        // Inspect '/'-delimited components for traversal in both modes: a '.' or '..' component
        // anywhere in the value (e.g. "../admin") is a traversal attempt and must be rejected
        // outright. For single-segment values the raw '/' is encoded below anyway; for catch-all
        // values this is the only guard against "a/../b" collapsing past the template prefix.
        var segments = value.Split('/');
        foreach (var segment in segments)
        {
            if (segment is "." or "..")
            {
                throw new InvalidRouteValueException("Route value contains a path-traversal segment ('.' or '..').");
            }
        }

        if (catchAll)
        {
            // Subtree proxy: keep '/' as a real separator so nested paths forward intact, but
            // encode each segment so a segment can never pivot the authority (e.g. "@evil.com"
            // -> "%40evil.com"). EnsureWithinTemplateBoundary re-checks the assembled URL.
            return string.Join('/', segments.Select(Uri.EscapeDataString));
        }

        // Encode the entire value as a single path segment. Uri.EscapeDataString encodes '/'
        // to %2F, so a route value can never introduce a new path segment or pivot the
        // authority (e.g. "@evil.com", "a/b" -> "%40evil.com", "a%2Fb").
        return Uri.EscapeDataString(value);
    }

    /// <summary>
    /// Defense-in-depth: after substitution, parse the result and verify the URI's
    /// scheme + authority + path prefix still match the static prefix of the template
    /// (everything up to the first <c>{...}</c> placeholder). If a substitution
    /// somehow escaped per-segment encoding and changed the host or jumped above
    /// the template prefix, this final check rejects it.
    /// </summary>
    private static void EnsureWithinTemplateBoundary(string template, string interpolated)
    {
        var firstPlaceholder = template.IndexOf('{');
        var staticPrefix = firstPlaceholder < 0 ? template : template[..firstPlaceholder];

        if (Uri.TryCreate(interpolated, UriKind.Absolute, out var interpolatedUri) &&
            Uri.TryCreate(staticPrefix, UriKind.Absolute, out var prefixUri))
        {
            if (!string.Equals(interpolatedUri.Scheme, prefixUri.Scheme, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(interpolatedUri.Host, prefixUri.Host, StringComparison.OrdinalIgnoreCase) ||
                interpolatedUri.Port != prefixUri.Port)
            {
                throw new InvalidRouteValueException("Interpolation moved the backend URL to a different scheme/host/port than the configured template.");
            }

            // Compare canonical paths: the resolved (Uri-canonicalized) path must still
            // begin with the canonicalized static prefix path. AbsoluteUri canonicalizes
            // ../ traversals away, so an escaped substitution would shorten the path here.
            var prefixPath = prefixUri.AbsolutePath;
            var resolvedPath = interpolatedUri.AbsolutePath;
            if (!resolvedPath.StartsWith(prefixPath, StringComparison.Ordinal))
            {
                throw new InvalidRouteValueException("Interpolation moved the backend URL outside the configured path prefix.");
            }
            return;
        }

        // Relative template: parse against a synthetic base so Uri canonicalization still
        // runs (collapsing any ../ that slipped through), then verify the canonicalized
        // path still starts with the template's static prefix.
        const string Sentinel = "https://__bff-relative-template__/";
        var prefixUnderBase = Sentinel + staticPrefix.TrimStart('/');
        var interpolatedUnderBase = Sentinel + interpolated.TrimStart('/');
        if (!Uri.TryCreate(prefixUnderBase, UriKind.Absolute, out var basePrefixUri) ||
            !Uri.TryCreate(interpolatedUnderBase, UriKind.Absolute, out var baseInterpolatedUri))
        {
            throw new InvalidRouteValueException("Interpolated route value could not be parsed for boundary validation.");
        }

        if (!baseInterpolatedUri.AbsolutePath.StartsWith(basePrefixUri.AbsolutePath, StringComparison.Ordinal))
        {
            throw new InvalidRouteValueException("Interpolation moved the backend URL outside the configured path prefix.");
        }
    }
}

/// <summary>
/// Thrown when a route value would, if substituted into a backend URL template,
/// cross a security boundary (path traversal, host change, query/fragment smuggling).
/// </summary>
internal sealed class InvalidRouteValueException(string message) : Exception(message);
