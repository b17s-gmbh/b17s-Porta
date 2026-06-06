namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Configuration options for reference token authentication
/// </summary>
public sealed class ReferenceTokenAuthOptions
{
    /// <summary>
    /// Header name containing the token (default: "Authorization")
    /// </summary>
    public string TokenHeaderName { get; set; } = "Authorization";

    /// <summary>
    /// Token prefix in the header (default: "Bearer ")
    /// </summary>
    public string TokenPrefix { get; set; } = "Bearer ";

    /// <summary>
    /// OIDC authority URL for introspection endpoint discovery
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Client ID for introspection authentication
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Client secret for introspection authentication
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Whether to use HTTP Basic authentication for introspection (default: true)
    /// If false, client_id and client_secret will be sent in the request body
    /// </summary>
    public bool UseBasicAuthForIntrospection { get; set; } = true;

    /// <summary>
    /// Token type hint for introspection (e.g., "access_token", "refresh_token")
    /// </summary>
    public string? TokenTypeHint { get; set; } = "access_token";

    /// <summary>
    /// Default cache duration for introspection results (default: 5 minutes)
    /// </summary>
    public TimeSpan DefaultCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum cache duration for introspection results (default: 1 hour)
    /// </summary>
    public TimeSpan MaxCacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Cache duration for negative introspection results - tokens the IdP reports as
    /// inactive, or whose response fails audience/issuer binding (default: 30 seconds).
    /// <para>
    /// Without negative caching, every request bearing a revoked or unknown token re-hits
    /// the introspection endpoint, letting an attacker spray random tokens to amplify load
    /// on the IdP. Setting this to <see cref="TimeSpan.Zero"/> disables negative caching.
    /// Keep the value short so a token that becomes valid (e.g. issuance race) is not
    /// rejected for long.
    /// </para>
    /// </summary>
    public TimeSpan NegativeCacheDuration { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Expected audience values. When <see cref="ValidateAudience"/> is true, the introspection
    /// response's <c>aud</c> claim must match one of these values; otherwise the token is rejected.
    /// Without this binding, any active token issued by the same authority for any other relying
    /// party would be accepted by this BFF (RFC 7662 audience confusion).
    /// </summary>
    public IList<string> ValidAudiences { get; set; } = [];

    /// <summary>
    /// Allow-list of <c>client_id</c> values that may have minted tokens accepted by this BFF.
    /// When non-empty, the introspection response's <c>client_id</c> claim must appear in this list.
    /// Use as an alternative or supplement to <see cref="ValidAudiences"/> when the IdP returns
    /// <c>client_id</c> but no <c>aud</c>.
    /// </summary>
    public IList<string> ValidClientIds { get; set; } = [];

    /// <summary>
    /// Expected issuer values. When <see cref="ValidateIssuer"/> is true, the introspection response's
    /// <c>iss</c> claim must match one of these values (or <see cref="Authority"/> when this list is empty).
    /// </summary>
    public IList<string> ValidIssuers { get; set; } = [];

    /// <summary>
    /// Whether to validate the <c>aud</c>/<c>client_id</c> claims on introspection responses (default: true).
    /// Disabling this re-introduces the audience-confusion class of vulnerability and is only safe when
    /// the introspection endpoint is dedicated to a single relying party.
    /// </summary>
    public bool ValidateAudience { get; set; } = true;

    /// <summary>
    /// Whether to validate the <c>iss</c> claim on introspection responses (default: true).
    /// </summary>
    public bool ValidateIssuer { get; set; } = true;
}
