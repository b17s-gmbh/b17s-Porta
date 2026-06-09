using System.Text.Json.Serialization;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Result of a token exchange operation.
/// </summary>
public readonly struct TokenExchangeResult
{
    /// <summary>Whether the token exchange succeeded.</summary>
    public bool IsSuccess { get; }

    /// <summary>The exchanged token response on success; <see langword="null"/> on failure.</summary>
    public TokenExchangeResponse? Response { get; }

    /// <summary>A non-secret error description on failure; <see langword="null"/> on success.</summary>
    public string? Error { get; }

    private TokenExchangeResult(bool isSuccess, TokenExchangeResponse? response, string? error)
    {
        IsSuccess = isSuccess;
        Response = response;
        Error = error;
    }

    /// <summary>
    /// Creates a successful result wrapping the exchanged token response.
    /// </summary>
    /// <param name="response">The token response returned by the STS.</param>
    /// <returns>A successful <see cref="TokenExchangeResult"/>.</returns>
    public static TokenExchangeResult Success(TokenExchangeResponse response) => new(true, response, null);

    /// <summary>
    /// Creates a failed result with the given non-secret error description.
    /// </summary>
    /// <param name="error">A non-secret error description; must not include token contents or response bodies.</param>
    /// <returns>A failed <see cref="TokenExchangeResult"/>.</returns>
    public static TokenExchangeResult Failure(string error) => new(false, null, error);
}

/// <summary>
/// Response from OAuth2 token exchange/refresh endpoints
/// </summary>
public sealed class TokenExchangeResponse
{
    /// <summary>
    /// The issued access token (OAuth2 <c>access_token</c>). Secret-classified; never log this value.
    /// </summary>
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// The token type (OAuth2 <c>token_type</c>), typically <c>Bearer</c>.
    /// </summary>
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// RFC 8693 <c>issued_token_type</c>: the token-type URN identifying what the STS actually
    /// issued. Required by the spec; used to confirm the exchange returned an access token rather
    /// than a refresh/id token or some other artifact.
    /// </summary>
    [JsonPropertyName("issued_token_type")]
    public string? IssuedTokenType { get; set; }

    /// <summary>
    /// The access token's lifetime in seconds (OAuth2 <c>expires_in</c>), relative to <see cref="IssuedAt"/>.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    /// <summary>
    /// The refresh token (OAuth2 <c>refresh_token</c>), if the STS issued one; otherwise empty.
    /// Secret-classified; never log this value.
    /// </summary>
    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;

    /// <summary>
    /// The ID token (OIDC <c>id_token</c>), if returned; otherwise empty. Secret-classified; never log this value.
    /// </summary>
    [JsonPropertyName("id_token")]
    public string IdToken { get; set; } = string.Empty;

    /// <summary>
    /// The granted scopes (OAuth2 <c>scope</c>), if returned by the STS; otherwise <see langword="null"/>.
    /// </summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    /// <summary>
    /// When this token response was issued (for cache TTL calculation)
    /// </summary>
    [JsonIgnore]
    public DateTimeOffset IssuedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Whether the token is expired or near expiry, given a clock skew.
    /// A token whose remaining lifetime (relative to <see cref="IssuedAt"/> +
    /// <see cref="ExpiresIn"/>) is less than or equal to <paramref name="skew"/>
    /// is treated as expired. Callers should pass the unified
    /// <c>PortaCoreOptions.TokenRefreshSkew</c> so all layers agree on staleness.
    /// Uses <see cref="TimeProvider.System"/>; for tests, call the overload that
    /// accepts an explicit <see cref="TimeProvider"/>.
    /// </summary>
    public bool IsExpiredWithSkew(TimeSpan skew)
        => IsExpiredWithSkew(skew, TimeProvider.System);

    /// <summary>
    /// Whether the token is expired or near expiry, given a clock skew, using
    /// the supplied <see cref="TimeProvider"/> as the time source.
    /// </summary>
    public bool IsExpiredWithSkew(TimeSpan skew, TimeProvider timeProvider)
        => timeProvider.GetUtcNow().Add(skew) >= IssuedAt.AddSeconds(ExpiresIn);
}
