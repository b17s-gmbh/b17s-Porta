namespace b17s.Porta.Configuration;

/// <summary>
/// Authentication configuration
/// </summary>
public sealed class AuthenticationConfiguration
{
    /// <summary>
    /// Authentication provider type (for backward compatibility with single provider)
    /// When using multi-provider setup, use DefaultProvider instead
    /// </summary>
    public string Provider { get; set; } = "session-based";

    /// <summary>
    /// Default authentication provider to use when no specific provider is configured
    /// Example: "session", "reference-token", "custom"
    /// </summary>
    public string? DefaultProvider { get; set; }

    /// <summary>
    /// Fallback chain of providers to try in order when provider selection strategies fail
    /// Example: ["session", "reference-token", "custom"]
    /// </summary>
    public List<string> ProviderFallbackChain { get; set; } = [];

    /// <summary>
    /// Session key for access token
    /// </summary>
    public string TokenSessionKey { get; set; } = "ACCESS_TOKEN";

    /// <summary>
    /// Session key for refresh token
    /// </summary>
    public string RefreshTokenSessionKey { get; set; } = "REFRESH_TOKEN";

    /// <summary>
    /// Additional authentication options
    /// </summary>
    public Dictionary<string, object> Options { get; set; } = [];
}
