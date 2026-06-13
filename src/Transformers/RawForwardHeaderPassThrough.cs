namespace b17s.Porta.Transformers;

/// <summary>
/// Configures which sensitive headers are allowed to be forwarded to backends in raw-forward
/// mode, and to which backend hosts. Headers not on the allow-list (Cookie, Authorization,
/// the standard Forwarded header, and the X-Forwarded-* family) are stripped before the request
/// is sent. The forwarding-metadata headers (Forwarded, X-Forwarded-*) are additionally relayed
/// when the inbound connection comes from a proxy listed in <see cref="TrustedForwardingProxies"/>.
/// Symmetrically, sensitive backend response headers (Set-Cookie, Strict-Transport-Security,
/// Content-Security-Policy, Server, X-Powered-By) are stripped on the way back to the client
/// unless added to <see cref="AllowedResponseHeaders"/>.
/// </summary>
public sealed class RawForwardHeaderPassThrough
{
    /// <summary>
    /// Header names to forward despite the default-strip list. Case-insensitive.
    /// Example: ["Authorization"] to allow client-supplied Authorization headers through.
    /// </summary>
    public HashSet<string> AllowedHeaders { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Backend host names that allowed headers may be forwarded to. Case-insensitive,
    /// matched against the destination URL host. If empty, AllowedHeaders apply to all
    /// destinations. If non-empty, AllowedHeaders only pass through when the destination
    /// host is in this set.
    /// </summary>
    public HashSet<string> AllowedDestinationHosts { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Backend response header names that should be forwarded to the client despite the
    /// default-strip list (Set-Cookie, Strict-Transport-Security, Content-Security-Policy,
    /// Server, X-Powered-By). Case-insensitive. Allowing Set-Cookie lets a backend plant
    /// cookies on the BFF's domain, which can shadow the BFF session cookie; opt in only
    /// when you understand and accept that risk.
    /// </summary>
    public HashSet<string> AllowedResponseHeaders { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// IP addresses or CIDR ranges of trusted reverse proxies that sit in front of the BFF.
    /// When the inbound connection's remote IP matches one of these, the client-supplied
    /// forwarding-metadata headers (the standard <c>Forwarded</c> header and the
    /// <c>X-Forwarded-*</c> family) are relayed to the backend instead of being stripped, so
    /// a legitimate front proxy's forwarding chain reaches the backend intact.
    /// <para>
    /// Entries may be single addresses (<c>"10.0.0.5"</c>, <c>"::1"</c>) or CIDR ranges
    /// (<c>"10.0.0.0/8"</c>, <c>"fd00::/8"</c>). IPv4-mapped IPv6 remote addresses are
    /// normalized before comparison, so an IPv4 entry matches a dual-stack
    /// <c>::ffff:10.0.0.5</c> peer.
    /// </para>
    /// <para>
    /// SECURITY: leave this empty unless the BFF is genuinely behind a reverse proxy. Any host
    /// listed here is fully trusted to dictate the forwarded client IP, host, and scheme that
    /// downstream backends (and their forwarded-header middleware) may act on. Listing a broad
    /// range or an untrusted network lets clients spoof that metadata.
    /// </para>
    /// </summary>
    public HashSet<string> TrustedForwardingProxies { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
