namespace b17s.Porta.Services;

/// <summary>
/// Service for validating reference (opaque) tokens via introspection endpoint.
/// </summary>
public interface IReferenceTokenService
{
    /// <summary>
    /// Introspects a reference token to validate it and retrieve its claims.
    /// </summary>
    /// <param name="token">The opaque token to introspect.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The introspection response, or null if introspection failed.</returns>
    Task<ReferenceTokenIntrospectionResult?> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of a reference token introspection request.
/// </summary>
public sealed class ReferenceTokenIntrospectionResult
{
    /// <summary>
    /// Whether the token is currently active.
    /// </summary>
    public bool IsActive { get; init; }

    /// <summary>
    /// Token expiration time, if available.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// Claims extracted from the introspection response.
    /// </summary>
    public Dictionary<string, string> Claims { get; init; } = [];
}
