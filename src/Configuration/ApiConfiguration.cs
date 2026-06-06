namespace b17s.Porta.Configuration;

/// <summary>
/// Configuration for API-specific authentication and token exchange
/// </summary>
public sealed class ApiConfiguration
{
    /// <summary>
    /// The API path prefix that this configuration applies to
    /// </summary>
    public string ApiPath { get; set; } = string.Empty;

    /// <summary>
    /// The scopes required for this API
    /// </summary>
    public string ApiScopes { get; set; } = string.Empty;

    /// <summary>
    /// The audience claim for this API
    /// </summary>
    public string ApiAudience { get; set; } = string.Empty;

    /// <summary>
    /// Client ID for API-specific authentication (optional, falls back to global)
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Client secret for API-specific authentication (optional, falls back to global)
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Token endpoint for API-specific authentication (optional, falls back to global)
    /// </summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>
    /// Whether to require authentication for this API
    /// </summary>
    public bool RequireAuthentication { get; set; } = true;

}
