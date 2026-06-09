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
    /// <returns>
    /// The authorization server's verdict, or <see langword="null"/> if introspection produced
    /// no verdict at all (authority not configured, introspection endpoint not discoverable,
    /// non-success response from the identity provider, or a malformed/oversized response body).
    /// </returns>
    /// <remarks>
    /// <see langword="null"/> means "unable to ask", not "token is inactive". A definitively
    /// inactive token yields a non-null result with
    /// <see cref="ReferenceTokenIntrospectionResult.IsActive"/> set to <see langword="false"/>.
    /// Callers must keep the two apart: only a definitive inactive verdict is safe to cache
    /// negatively, while a <see langword="null"/> (e.g. a transient identity-provider outage)
    /// should fail closed for the current request and be retried on the next one.
    /// </remarks>
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
