using System.Text.Json.Serialization;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Result of a token exchange operation.
/// </summary>
public readonly struct TokenExchangeResult
{
    public bool IsSuccess { get; }
    public TokenExchangeResponse? Response { get; }
    public string? Error { get; }

    private TokenExchangeResult(bool isSuccess, TokenExchangeResponse? response, string? error)
    {
        IsSuccess = isSuccess;
        Response = response;
        Error = error;
    }

    public static TokenExchangeResult Success(TokenExchangeResponse response) => new(true, response, null);
    public static TokenExchangeResult Failure(string error) => new(false, null, error);
}

/// <summary>
/// Response from OAuth2 token exchange/refresh endpoints
/// </summary>
public sealed class TokenExchangeResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// RFC 8693 <c>issued_token_type</c>: the token-type URN identifying what the STS actually
    /// issued. Required by the spec; used to confirm the exchange returned an access token rather
    /// than a refresh/id token or some other artifact.
    /// </summary>
    [JsonPropertyName("issued_token_type")]
    public string? IssuedTokenType { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;

    [JsonPropertyName("id_token")]
    public string IdToken { get; set; } = string.Empty;

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
