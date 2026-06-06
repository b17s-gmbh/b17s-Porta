using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Tokens;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace b17s.Porta.Tests.Auth.Tokens;

public class JwtValidationHelperTests
{
    private const string Authority = "https://idp.example.com";
    private const string Audience = "test-client";
    private const string Issuer = "https://idp.example.com";

    [Fact]
    public async Task ValidateAsync_ValidToken_Succeeds()
    {
        var ctx = new ValidationFixture();
        var token = ctx.IssueToken(audience: Audience);

        var result = await JwtValidationHelper.ValidateAsync(
            token, ctx.Discovery, ctx.Parameters(), NullLogger.Instance, TestContext.Current.CancellationToken);

        Assert.True(result.IsValid);
        Assert.Equal(JwtValidationFailureReason.None, result.Reason);
        Assert.NotNull(result.Token);
    }

    [Fact]
    public async Task ValidateAsync_AuthorityNotConfigured_FailsAuthorityNotConfigured()
    {
        var ctx = new ValidationFixture();
        var token = ctx.IssueToken(audience: Audience);

        var parameters = ctx.Parameters() with { Authority = string.Empty };
        var result = await JwtValidationHelper.ValidateAsync(
            token, ctx.Discovery, parameters, NullLogger.Instance, TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal(JwtValidationFailureReason.AuthorityNotConfigured, result.Reason);
    }

    [Fact]
    public async Task ValidateAsync_DiscoveryReturnsNull_FailsDiscoveryFailed()
    {
        var ctx = new ValidationFixture { Discovery = new NullDiscoveryService() };
        var token = ctx.IssueToken(audience: Audience);

        var result = await JwtValidationHelper.ValidateAsync(
            token, ctx.Discovery, ctx.Parameters(), NullLogger.Instance, TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal(JwtValidationFailureReason.DiscoveryFailed, result.Reason);
    }

    [Fact]
    public async Task ValidateAsync_WrongIssuer_FailsIssuerInvalid()
    {
        var ctx = new ValidationFixture();
        var token = ctx.IssueToken(audience: Audience, issuer: "https://attacker.example.com");

        var result = await JwtValidationHelper.ValidateAsync(
            token, ctx.Discovery, ctx.Parameters(), NullLogger.Instance, TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal(JwtValidationFailureReason.IssuerInvalid, result.Reason);
    }

    [Fact]
    public async Task ValidateAsync_WrongAudience_FailsAudienceInvalid()
    {
        var ctx = new ValidationFixture();
        var token = ctx.IssueToken(audience: "different-client");

        var result = await JwtValidationHelper.ValidateAsync(
            token, ctx.Discovery, ctx.Parameters(), NullLogger.Instance, TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal(JwtValidationFailureReason.AudienceInvalid, result.Reason);
    }

    [Fact]
    public async Task ValidateAsync_ExpiredToken_FailsExpired()
    {
        var ctx = new ValidationFixture();
        var token = ctx.IssueToken(
            audience: Audience,
            notBefore: DateTime.UtcNow.AddHours(-2),
            expires: DateTime.UtcNow.AddHours(-1));

        var result = await JwtValidationHelper.ValidateAsync(
            token, ctx.Discovery, ctx.Parameters(), NullLogger.Instance, TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal(JwtValidationFailureReason.Expired, result.Reason);
    }

    [Fact]
    public async Task ValidateAsync_TamperedSignature_FailsSignatureInvalid()
    {
        var ctx = new ValidationFixture();
        var token = ctx.IssueToken(audience: Audience);
        // Tamper the last 5 chars of the signature segment.
        var parts = token.Split('.');
        var sig = parts[2];
        parts[2] = sig[..^5] + new string('A', 5);
        var tampered = string.Join('.', parts);

        var result = await JwtValidationHelper.ValidateAsync(
            tampered, ctx.Discovery, ctx.Parameters(), NullLogger.Instance, TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal(JwtValidationFailureReason.SignatureInvalid, result.Reason);
    }

    [Fact]
    public async Task ValidateAsync_NonceMismatch_FailsNonceMismatch()
    {
        var ctx = new ValidationFixture();
        var token = ctx.IssueToken(audience: Audience, nonce: "expected-nonce");

        var parameters = ctx.Parameters() with { ExpectedNonce = "different-nonce" };
        var result = await JwtValidationHelper.ValidateAsync(
            token, ctx.Discovery, parameters, NullLogger.Instance, TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal(JwtValidationFailureReason.NonceMismatch, result.Reason);
    }

    [Fact]
    public async Task ValidateAsync_MatchingNonce_Succeeds()
    {
        var ctx = new ValidationFixture();
        var token = ctx.IssueToken(audience: Audience, nonce: "expected-nonce");

        var parameters = ctx.Parameters() with { ExpectedNonce = "expected-nonce" };
        var result = await JwtValidationHelper.ValidateAsync(
            token, ctx.Discovery, parameters, NullLogger.Instance, TestContext.Current.CancellationToken);

        Assert.True(result.IsValid);
    }

    private sealed class ValidationFixture
    {
        private readonly RsaSecurityKey _signingKey;

        public ValidationFixture()
        {
            using var rsa = RSA.Create(2048);
            _signingKey = new RsaSecurityKey(rsa.ExportParameters(true)) { KeyId = "test-key" };
            Discovery = new InMemoryDiscoveryService(_signingKey);
        }

        public IDiscoveryService Discovery { get; set; }

        public JwtValidationParameters Parameters() => new()
        {
            Authority = Authority,
            Audience = Audience,
            ClockSkew = TimeSpan.FromSeconds(0),
        };

        public string IssueToken(
            string audience,
            string? issuer = null,
            string? nonce = null,
            DateTime? notBefore = null,
            DateTime? expires = null)
        {
            var creds = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);
            var claims = new List<Claim> { new("sub", "user-123") };
            if (nonce is not null)
            {
                claims.Add(new Claim("nonce", nonce));
            }

            var jwt = new JwtSecurityToken(
                issuer: issuer ?? Issuer,
                audience: audience,
                claims: claims,
                notBefore: notBefore ?? DateTime.UtcNow.AddMinutes(-1),
                expires: expires ?? DateTime.UtcNow.AddHours(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
    }

    private sealed class InMemoryDiscoveryService(SecurityKey signingKey) : IDiscoveryService
    {
        public Task<OpenIdConnectConfiguration?> GetConfigurationAsync(string authority, CancellationToken cancellationToken = default)
        {
            var config = new OpenIdConnectConfiguration
            {
                Issuer = Issuer,
            };
            config.SigningKeys.Add(signingKey);
            return Task.FromResult<OpenIdConnectConfiguration?>(config);
        }
    }

    private sealed class NullDiscoveryService : IDiscoveryService
    {
        public Task<OpenIdConnectConfiguration?> GetConfigurationAsync(string authority, CancellationToken cancellationToken = default)
            => Task.FromResult<OpenIdConnectConfiguration?>(null);
    }
}
