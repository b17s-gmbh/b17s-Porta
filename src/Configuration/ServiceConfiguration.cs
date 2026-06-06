namespace b17s.Porta.Configuration;

/// <summary>
/// Configuration for a backend service
/// </summary>
public sealed class ServiceConfiguration
{
    /// <summary>
    /// Unique name for this service
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Base endpoint URL
    /// </summary>
    public string Endpoint { get; set; } = string.Empty;

    /// <summary>
    /// Health check endpoint
    /// </summary>
    public string? HealthCheckPath { get; set; }

    /// <summary>
    /// Timeout for requests to this service
    /// </summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// API-specific authentication and token exchange configurations
    /// </summary>
    public List<ApiConfiguration> ApiConfigurations { get; set; } = [];
}
