namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Configuration options for JWT bearer authentication.
/// </summary>
/// <remarks>
/// JWT validation is performed by ASP.NET Core's built-in <c>AddJwtBearer</c> handler. Signing keys
/// are discovered from the configured <see cref="Authority"/> via OIDC metadata
/// (<c>/.well-known/openid-configuration</c> + JWKS endpoint), cached, and rotated automatically by
/// its <c>ConfigurationManager</c> (an unknown <c>kid</c> also triggers an out-of-band refresh).
/// Inbound tokens are read from the standard <c>Authorization: Bearer</c> header. Reference token
/// authentication is the recommended default; opt into JWT only when reference tokens / introspection
/// are not available in your environment.
/// </remarks>
public sealed class JwtBearerAuthOptions
{
    /// <summary>
    /// OIDC authority URL. Used to discover the JWKS endpoint and (when <see cref="ValidateIssuer"/>
    /// is true and <see cref="ValidIssuers"/> is empty) the expected issuer.
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Whether to require HTTPS for the OIDC metadata endpoint (default: true).
    /// Set to false only for local development against a non-HTTPS IdP.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Expected audience values for the token. At least one must match when
    /// <see cref="ValidateAudience"/> is true.
    /// </summary>
    public IList<string> ValidAudiences { get; set; } = [];

    /// <summary>
    /// Explicit list of accepted issuers. When empty and <see cref="ValidateIssuer"/> is true,
    /// the issuer from OIDC metadata at <see cref="Authority"/> is used.
    /// </summary>
    public IList<string> ValidIssuers { get; set; } = [];

    /// <summary>
    /// Whether to validate the <c>iss</c> claim (default: true).
    /// </summary>
    public bool ValidateIssuer { get; set; } = true;

    /// <summary>
    /// Whether to validate the <c>aud</c> claim against <see cref="ValidAudiences"/> (default: true).
    /// </summary>
    public bool ValidateAudience { get; set; } = true;

    /// <summary>
    /// Whether to validate the token lifetime (<c>exp</c>, <c>nbf</c>) (default: true).
    /// </summary>
    public bool ValidateLifetime { get; set; } = true;

    /// <summary>
    /// Allowed clock skew when validating <c>exp</c>/<c>nbf</c> (default: 30 seconds).
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);
}
