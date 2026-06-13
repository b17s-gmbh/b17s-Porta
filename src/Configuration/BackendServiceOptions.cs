namespace b17s.Porta.Configuration;

/// <summary>
/// Configuration for a backend service used by the built-in BasicAuth handler.
/// For more advanced scenarios, implement a custom IBackendAuthHandler.
/// </summary>
public sealed class BackendServiceOptions
{
    /// <summary>
    /// The default configuration section name (<c>"BackendService"</c>) this options type binds to.
    /// </summary>
    public const string SectionName = "BackendService";

    /// <summary>
    /// Base URL of the backend service. Used as the destination host for the built-in
    /// BasicAuth handler and as the default target for single-backend deployments.
    /// </summary>
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// Default Basic auth credentials, used when no per-backend entry matches the
    /// current request's backend name. Kept for backwards compatibility with
    /// single-backend deployments.
    /// </summary>
    public BasicAuthOptions BasicAuth { get; set; } = new();

    /// <summary>
    /// Per-backend Basic auth credentials, keyed by the backend name supplied via
    /// <c>BackendRequest.BackendName</c>. When the name matches, these credentials
    /// override <see cref="BasicAuth"/>; otherwise see <see cref="AllowGlobalBasicAuthFallback"/>.
    /// </summary>
    public Dictionary<string, BasicAuthOptions> Backends { get; set; }
        = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Controls what happens when a request names a specific backend (via
    /// <c>BackendRequest.BackendName</c>) that has no matching entry in <see cref="Backends"/>.
    /// <para>
    /// Default <c>false</c> (fail closed): the BasicAuth handler sends no <c>Authorization</c>
    /// header rather than falling back to the global <see cref="BasicAuth"/> default - which could
    /// silently forward credentials intended for a different host. Set <c>true</c> to restore the
    /// legacy behaviour where named backends without their own credentials share the global default.
    /// </para>
    /// <para>
    /// This setting does not affect requests that carry no backend name at all; those always use
    /// <see cref="BasicAuth"/>, since that is the unambiguous single-backend / default configuration.
    /// </para>
    /// </summary>
    public bool AllowGlobalBasicAuthFallback { get; set; }

    /// <summary>
    /// Default audience used by the built-in TokenExchange auth handler when an
    /// endpoint declares <c>BackendAuthPolicies.TokenExchange</c> without supplying
    /// an audience inline (i.e. via <c>WithTokenExchange(audience)</c>). When set,
    /// applies to any backend that doesn't override it via
    /// <see cref="TokenExchangeAudiences"/>.
    /// </summary>
    public string? DefaultTokenExchangeAudience { get; set; }

    /// <summary>
    /// Per-backend token exchange audiences, keyed by the backend name supplied via
    /// <c>BackendRequest.BackendName</c>. When the name matches, this audience is
    /// used; otherwise the handler falls back to
    /// <see cref="DefaultTokenExchangeAudience"/>.
    /// </summary>
    public Dictionary<string, string> TokenExchangeAudiences { get; set; }
        = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Basic authentication credentials.
/// </summary>
public sealed class BasicAuthOptions
{
    /// <summary>
    /// The user name sent in the <c>Authorization: Basic</c> header.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// The password sent in the <c>Authorization: Basic</c> header. Secret-classified - never log this value.
    /// </summary>
    public string Password { get; set; } = string.Empty;
}
