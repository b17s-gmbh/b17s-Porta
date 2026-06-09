using b17s.Porta.Auth.Discovery;

using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Parameters for validating a JWT issued by the OIDC authority.
/// </summary>
public record JwtValidationParameters
{
    /// <summary>
    /// The OIDC authority (issuer) URL. Used to fetch discovery metadata and signing keys, and as
    /// the expected issuer when <see cref="ValidateIssuer"/> is enabled.
    /// </summary>
    public required string Authority { get; init; }

    /// <summary>
    /// The audience the token must be issued for, checked when <see cref="ValidateAudience"/> is enabled.
    /// </summary>
    public required string Audience { get; init; }

    /// <summary>
    /// Whether to validate that the token's issuer matches the authority's discovered issuer. Defaults to <see langword="true"/>.
    /// </summary>
    public bool ValidateIssuer { get; init; } = true;

    /// <summary>
    /// Whether to validate that the token's audience contains <see cref="Audience"/>. Defaults to <see langword="true"/>.
    /// </summary>
    public bool ValidateAudience { get; init; } = true;

    /// <summary>
    /// Whether to require and verify the token's signature against the authority's signing keys.
    /// Defaults to <see langword="true"/>. Disabling this removes the signature trust check and
    /// should only be done in tests.
    /// </summary>
    public bool ValidateSignature { get; init; } = true;

    /// <summary>
    /// Whether to validate the token's lifetime (<c>nbf</c>/<c>exp</c>), allowing for <see cref="ClockSkew"/>. Defaults to <see langword="true"/>.
    /// </summary>
    public bool ValidateLifetime { get; init; } = true;

    /// <summary>
    /// Permitted clock skew applied to lifetime validation to tolerate small clock differences
    /// between the BFF and the authority. Defaults to five minutes.
    /// </summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// When set, the token's <c>nonce</c> claim must equal this value; otherwise validation fails
    /// with <see cref="JwtValidationFailureReason.NonceMismatch"/>. Used for id_token replay
    /// protection in the auth-code callback flow. When <see langword="null"/>, no nonce check is performed.
    /// </summary>
    public string? ExpectedNonce { get; init; }
}

/// <summary>
/// Result of a JWT validation attempt. Either succeeds with the parsed token,
/// or fails with a categorized reason for diagnostics and HTTP-status mapping.
/// </summary>
public enum JwtValidationFailureReason
{
    /// <summary>No failure; the token validated successfully.</summary>
    None,

    /// <summary>No OIDC authority was configured, so validation could not be attempted.</summary>
    AuthorityNotConfigured,

    /// <summary>OIDC discovery metadata (including signing keys) could not be retrieved from the authority.</summary>
    DiscoveryFailed,

    /// <summary>The token's signature did not verify against the authority's signing keys.</summary>
    SignatureInvalid,

    /// <summary>The token's issuer did not match the authority's discovered issuer.</summary>
    IssuerInvalid,

    /// <summary>The token's audience did not contain the configured audience.</summary>
    AudienceInvalid,

    /// <summary>The token was expired (or not yet valid) beyond the permitted clock skew.</summary>
    Expired,

    /// <summary>The validated security token was not a JWT, or the token was malformed.</summary>
    NotJwt,

    /// <summary>The token's <c>nonce</c> claim did not match the expected value.</summary>
    NonceMismatch,

    /// <summary>Validation failed for some other reason not covered by the more specific categories.</summary>
    Other
}

/// <summary>
/// Outcome of a JWT validation attempt: either a success carrying the parsed token, or a failure
/// carrying a categorized <see cref="JwtValidationFailureReason"/> and an optional diagnostic message.
/// </summary>
/// <param name="Token">The parsed token on success; <see langword="null"/> on failure.</param>
/// <param name="Reason">The failure category, or <see cref="JwtValidationFailureReason.None"/> on success.</param>
/// <param name="ErrorMessage">An optional diagnostic message describing the failure; <see langword="null"/> on success.</param>
public readonly record struct JwtValidationResult(
    JsonWebToken? Token,
    JwtValidationFailureReason Reason,
    string? ErrorMessage)
{
    /// <summary>
    /// Whether validation succeeded: a token was parsed and the reason is
    /// <see cref="JwtValidationFailureReason.None"/>.
    /// </summary>
    public bool IsValid => Token != null && Reason == JwtValidationFailureReason.None;

    /// <summary>
    /// Creates a successful result for the given parsed token.
    /// </summary>
    /// <param name="token">The validated, parsed token.</param>
    /// <returns>A successful <see cref="JwtValidationResult"/>.</returns>
    public static JwtValidationResult Success(JsonWebToken token) => new(token, JwtValidationFailureReason.None, null);

    /// <summary>
    /// Creates a failed result with the given reason and optional diagnostic message.
    /// </summary>
    /// <param name="reason">The categorized failure reason.</param>
    /// <param name="message">An optional diagnostic message; never includes token contents.</param>
    /// <returns>A failed <see cref="JwtValidationResult"/>.</returns>
    public static JwtValidationResult Failure(JwtValidationFailureReason reason, string? message = null) => new(null, reason, message);
}

/// <summary>
/// Validates JWTs issued by the configured OIDC authority. Used for id_token
/// validation in the auth-code callback flow and for logout_token validation
/// in the back-channel logout endpoint.
/// </summary>
/// <remarks>
/// Uses <see cref="JsonWebTokenHandler"/> rather than the legacy
/// <see cref="System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler"/>. The two handlers
/// have subtly different claim-mapping behavior - the legacy handler silently remaps
/// <c>sub</c> to <c>ClaimTypes.NameIdentifier</c>, which led to mismatches with
/// <see cref="b17s.Porta.Auth.Providers.JwtBearerAuthProvider"/> (which already uses
/// <see cref="JsonWebTokenHandler"/>). Keep both code paths on the same handler so claim
/// types stay consistent across the library.
/// </remarks>
internal static class JwtValidationHelper
{
    private static readonly JsonWebTokenHandler Handler = new();

    /// <summary>
    /// Asymmetric signing algorithms accepted for OIDC-issued tokens. Pinning to RS/ES/PS
    /// rules out <c>none</c> and <c>HS*</c> regardless of what the JWKS advertises - defense-in-depth
    /// against algorithm-confusion attacks where an attacker tries to verify an HMAC-signed token
    /// against a public key.
    /// </summary>
    internal static readonly string[] AllowedAsymmetricAlgorithms =
    [
        SecurityAlgorithms.RsaSha256,
        SecurityAlgorithms.RsaSha384,
        SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.EcdsaSha256,
        SecurityAlgorithms.EcdsaSha384,
        SecurityAlgorithms.EcdsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256,
        SecurityAlgorithms.RsaSsaPssSha384,
        SecurityAlgorithms.RsaSsaPssSha512,
    ];

    public static async Task<JwtValidationResult> ValidateAsync(
        string token,
        IDiscoveryService discoveryService,
        JwtValidationParameters parameters,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(parameters.Authority))
        {
            return JwtValidationResult.Failure(JwtValidationFailureReason.AuthorityNotConfigured);
        }

        var oidcConfig = await discoveryService.GetConfigurationAsync(parameters.Authority, cancellationToken);
        if (oidcConfig == null)
        {
            return JwtValidationResult.Failure(JwtValidationFailureReason.DiscoveryFailed);
        }

        var tvp = new TokenValidationParameters
        {
            ValidateIssuer = parameters.ValidateIssuer,
            ValidIssuer = oidcConfig.Issuer,
            ValidateAudience = parameters.ValidateAudience,
            ValidAudience = parameters.Audience,
            ValidateIssuerSigningKey = parameters.ValidateSignature,
            IssuerSigningKeys = oidcConfig.SigningKeys,
            ValidateLifetime = parameters.ValidateLifetime,
            ClockSkew = parameters.ClockSkew,
            RequireSignedTokens = parameters.ValidateSignature,
            ValidAlgorithms = AllowedAsymmetricAlgorithms
        };

        var validationResult = await Handler.ValidateTokenAsync(token, tvp);
        if (!validationResult.IsValid)
        {
            return MapFailure(validationResult.Exception);
        }

        if (validationResult.SecurityToken is not JsonWebToken parsed)
        {
            return JwtValidationResult.Failure(JwtValidationFailureReason.NotJwt);
        }

        if (parameters.ExpectedNonce is not null)
        {
            var actualNonce = parsed.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;
            if (!string.Equals(actualNonce, parameters.ExpectedNonce, StringComparison.Ordinal))
            {
                return JwtValidationResult.Failure(JwtValidationFailureReason.NonceMismatch);
            }
        }

        return JwtValidationResult.Success(parsed);
    }

    private static JwtValidationResult MapFailure(Exception? exception) => exception switch
    {
        SecurityTokenInvalidSignatureException ex => JwtValidationResult.Failure(JwtValidationFailureReason.SignatureInvalid, ex.Message),
        SecurityTokenInvalidIssuerException ex => JwtValidationResult.Failure(JwtValidationFailureReason.IssuerInvalid, ex.Message),
        SecurityTokenInvalidAudienceException ex => JwtValidationResult.Failure(JwtValidationFailureReason.AudienceInvalid, ex.Message),
        SecurityTokenExpiredException ex => JwtValidationResult.Failure(JwtValidationFailureReason.Expired, ex.Message),
        SecurityTokenMalformedException ex => JwtValidationResult.Failure(JwtValidationFailureReason.NotJwt, ex.Message),
        SecurityTokenException ex => JwtValidationResult.Failure(JwtValidationFailureReason.Other, ex.Message),
        not null => JwtValidationResult.Failure(JwtValidationFailureReason.Other, exception.Message),
        _ => JwtValidationResult.Failure(JwtValidationFailureReason.Other, "Unknown validation failure")
    };
}
