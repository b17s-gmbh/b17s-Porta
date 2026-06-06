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
    public required string Authority { get; init; }
    public required string Audience { get; init; }
    public bool ValidateIssuer { get; init; } = true;
    public bool ValidateAudience { get; init; } = true;
    public bool ValidateSignature { get; init; } = true;
    public bool ValidateLifetime { get; init; } = true;
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);
    public string? ExpectedNonce { get; init; }
}

/// <summary>
/// Result of a JWT validation attempt. Either succeeds with the parsed token,
/// or fails with a categorized reason for diagnostics and HTTP-status mapping.
/// </summary>
public enum JwtValidationFailureReason
{
    None,
    AuthorityNotConfigured,
    DiscoveryFailed,
    SignatureInvalid,
    IssuerInvalid,
    AudienceInvalid,
    Expired,
    NotJwt,
    NonceMismatch,
    Other
}

public readonly record struct JwtValidationResult(
    JsonWebToken? Token,
    JwtValidationFailureReason Reason,
    string? ErrorMessage)
{
    public bool IsValid => Token != null && Reason == JwtValidationFailureReason.None;
    public static JwtValidationResult Success(JsonWebToken token) => new(token, JwtValidationFailureReason.None, null);
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
