namespace b17s.Porta.Auth.Providers;

/// <summary>
/// Contains authentication information for backend requests
/// </summary>
public sealed class AuthenticationContext
{
    /// <summary>
    /// Primary access token
    /// </summary>
    public string? AccessToken { get; set; }

    /// <summary>
    /// Refresh token for renewing access
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// ID token (OIDC)
    /// </summary>
    public string? IdToken { get; set; }

    /// <summary>
    /// Token expiration time
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>
    /// User claims/identity information, keyed by claim type. A single type may carry
    /// multiple values (e.g. multiple <c>role</c> claims), so values are stored as arrays
    /// rather than a single string. Use <c>TransformerContext.GetClaim</c> /
    /// <c>TransformerBase.GetClaim</c> for the first value of a type, or the corresponding
    /// <c>GetClaims</c> for every value.
    /// </summary>
    public Dictionary<string, string[]> Claims { get; set; } = [];

    /// <summary>
    /// Additional authentication headers
    /// </summary>
    public Dictionary<string, string> Headers { get; set; } = [];

    /// <summary>
    /// Indicates if the user is authenticated
    /// </summary>
    public bool IsAuthenticated => !string.IsNullOrEmpty(AccessToken);

    /// <summary>
    /// Identifier of the <see cref="Auth.Providers.IAuthenticationProvider"/> that issued
    /// this context. Set by <c>CompositeAuthenticationProvider</c> when a registered
    /// provider returns an authenticated context, and used to route subsequent
    /// <see cref="Auth.Providers.IAuthenticationProvider.RefreshAsync"/> calls back to
    /// the originating provider.
    /// </summary>
    public string? Scheme { get; set; }

    /// <summary>
    /// Indicates whether the access token is expired or near expiry, given a clock
    /// skew. Pass the unified <c>PortaCoreOptions.TokenRefreshSkew</c> so all layers
    /// (cookie-session refresh, API-token cache, providers) agree on staleness.
    /// Uses <see cref="TimeProvider.System"/>; for tests, call the overload that
    /// accepts an explicit <see cref="TimeProvider"/>.
    /// </summary>
    public bool IsExpiredWithSkew(TimeSpan skew)
        => IsExpiredWithSkew(skew, TimeProvider.System);

    /// <summary>
    /// Indicates whether the access token is expired or near expiry, given a clock
    /// skew, using the supplied <see cref="TimeProvider"/> as the time source.
    /// </summary>
    public bool IsExpiredWithSkew(TimeSpan skew, TimeProvider timeProvider)
        => ExpiresAt.HasValue && timeProvider.GetUtcNow().Add(skew) >= ExpiresAt.Value;

    /// <summary>
    /// Service-specific tokens (for different API scopes/audiences)
    /// </summary>
    public Dictionary<string, string> ServiceTokens { get; set; } = [];

    /// <summary>
    /// Creates an unauthenticated context with no tokens or claims.
    /// </summary>
    /// <returns>A new AuthenticationContext representing an unauthenticated state</returns>
    public static AuthenticationContext Unauthenticated() => new();
}
