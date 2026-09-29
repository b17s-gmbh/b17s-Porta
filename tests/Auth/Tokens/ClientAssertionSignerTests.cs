using System.Security.Cryptography;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Tests.Fixtures;

using Microsoft.IdentityModel.JsonWebTokens;

namespace b17s.Porta.Tests.Auth.Tokens;

/// <summary>
/// Tests for <see cref="ClientAssertionSigner"/>: every key format the supported IdPs hand out
/// (Zitadel key file, Okta/Keycloak PEM, Entra/Keycloak certificates and PKCS#12) must produce an
/// assertion that verifies against the matching public key, with the header parameters each IdP
/// looks for (<c>kid</c>, <c>x5t</c>, <c>x5t#S256</c>).
/// </summary>
public sealed class ClientAssertionSignerTests
{
    private const string Audience = "https://idp.test/oauth2/token";

    private static ClientAssertionSigner Load(PrivateKeyJwtOptions options) => ClientAssertionSigner.Load(options);

    private static string Sign(ClientAssertionSigner signer, string clientId = "client-1") =>
        signer.CreateAssertion(clientId, Audience, DateTimeOffset.UtcNow);

    [Fact]
    public async Task ZitadelKeyFile_UsesKeyIdAndClientIdFromFile()
    {
        using var key = TestSigningKey.Rsa();
        var signer = Load(new PrivateKeyJwtOptions { Key = key.ZitadelKeyFile(clientId: "app@project", keyId: "zkid") });

        Assert.Equal("app@project", signer.KeyFileClientId);
        var jwt = await key.ValidateAsync(Sign(signer, "app@project"), "app@project", Audience);
        Assert.Equal("RS256", jwt.Alg);
        Assert.Equal("zkid", jwt.Kid);
        Assert.Equal("app@project", jwt.Subject);
        Assert.False(jwt.TryGetHeaderValue<string>("x5t", out _));
    }

    [Fact]
    public async Task ZitadelKeyFile_ExplicitKeyId_Overrides()
    {
        using var key = TestSigningKey.Rsa();
        var signer = Load(new PrivateKeyJwtOptions { Key = key.ZitadelKeyFile(keyId: "zkid"), KeyId = "override" });

        var jwt = await key.ValidateAsync(Sign(signer), "client-1", Audience);
        Assert.Equal("override", jwt.Kid);
    }

    [Fact]
    public async Task Pkcs8Pem_WithKeyId_SignsRs256_WithKid()
    {
        // Okta: the console generates a key pair, shows a kid, and offers the private key as PKCS#8 PEM.
        using var key = TestSigningKey.Rsa();
        var signer = Load(new PrivateKeyJwtOptions { Key = key.Pkcs8Pem, KeyId = "okta-kid" });

        Assert.Null(signer.KeyFileClientId);
        var jwt = await key.ValidateAsync(Sign(signer), "client-1", Audience);
        Assert.Equal("RS256", jwt.Alg);
        Assert.Equal("okta-kid", jwt.Kid);
    }

    [Fact]
    public async Task Pkcs1Pem_WithoutKeyId_OmitsKid()
    {
        using var key = TestSigningKey.Rsa();
        var signer = Load(new PrivateKeyJwtOptions { Key = key.TraditionalPem });

        var jwt = await key.ValidateAsync(Sign(signer), "client-1", Audience);
        Assert.False(jwt.TryGetHeaderValue<string>("kid", out _));
    }

    [Theory]
    [InlineData("PS256")]
    [InlineData("RS384")]
    [InlineData("PS512")]
    public async Task RsaAlgorithmOverride_IsHonored(string algorithm)
    {
        using var key = TestSigningKey.Rsa();
        var signer = Load(new PrivateKeyJwtOptions { Key = key.Pkcs8Pem, Algorithm = algorithm });

        var jwt = await key.ValidateAsync(Sign(signer), "client-1", Audience);
        Assert.Equal(algorithm, jwt.Alg);
    }

    [Theory]
    [InlineData("P256", "ES256")]
    [InlineData("P384", "ES384")]
    [InlineData("P521", "ES512")]
    public async Task EcKey_AlgorithmFollowsCurve(string curveName, string expectedAlgorithm)
    {
        var curve = curveName switch
        {
            "P256" => ECCurve.NamedCurves.nistP256,
            "P384" => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        using var key = TestSigningKey.Ec(curve);
        var signer = Load(new PrivateKeyJwtOptions { Key = key.TraditionalPem });

        var jwt = await key.ValidateAsync(Sign(signer), "client-1", Audience);
        Assert.Equal(expectedAlgorithm, jwt.Alg);
    }

    [Fact]
    public async Task EcPkcs8Pem_IsSupported()
    {
        using var key = TestSigningKey.Ec(ECCurve.NamedCurves.nistP256);
        var signer = Load(new PrivateKeyJwtOptions { Key = key.Pkcs8Pem });

        await key.ValidateAsync(Sign(signer), "client-1", Audience);
    }

    [Fact]
    public void EcKey_MismatchedAlgorithm_Fails()
    {
        using var key = TestSigningKey.Ec(ECCurve.NamedCurves.nistP256);

        var ex = Assert.Throws<InvalidOperationException>(
            () => Load(new PrivateKeyJwtOptions { Key = key.TraditionalPem, Algorithm = "ES384" }));
        Assert.Contains("ES256", ex.Message);
    }

    [Fact]
    public void RsaKey_EcAlgorithm_Fails()
    {
        using var key = TestSigningKey.Rsa();

        var ex = Assert.Throws<InvalidOperationException>(
            () => Load(new PrivateKeyJwtOptions { Key = key.Pkcs8Pem, Algorithm = "ES256" }));
        Assert.Contains("not valid for an RSA key", ex.Message);
    }

    [Fact]
    public void RsaKeyBelow2048Bits_Fails()
    {
        using var key = TestSigningKey.Rsa(1024);

        var ex = Assert.Throws<InvalidOperationException>(() => Load(new PrivateKeyJwtOptions { Key = key.Pkcs8Pem }));
        Assert.Contains("2048", ex.Message);
    }

    [Fact]
    public async Task PemWithCertificate_SendsX5tAndX5tS256()
    {
        // Entra ID identifies the certificate credential by its thumbprint header.
        using var key = TestSigningKey.Rsa();
        var signer = Load(new PrivateKeyJwtOptions { Key = key.PemWithCertificate });

        Assert.True(signer.HasCertificate);
        var jwt = await key.ValidateAsync(Sign(signer), "client-1", Audience);
        Assert.Equal(key.X5t, jwt.GetHeaderValue<string>("x5t"));
        Assert.Equal(key.X5tS256, jwt.GetHeaderValue<string>("x5t#S256"));
    }

    [Fact]
    public void PemWithForeignCertificate_Fails()
    {
        // A certificate that does not belong to the key would send thumbprints the IdP rejects.
        using var key = TestSigningKey.Rsa();
        using var other = TestSigningKey.Rsa();
        var pem = key.Pkcs8Pem + "\n" + other.Certificate.ExportCertificatePem();

        var ex = Assert.Throws<InvalidOperationException>(() => Load(new PrivateKeyJwtOptions { Key = pem }));
        Assert.Contains("matches its private key", ex.Message);
    }

    [Fact]
    public async Task EncryptedPem_WithPassword_Loads()
    {
        using var key = TestSigningKey.Rsa();
        var signer = Load(new PrivateKeyJwtOptions { Key = key.EncryptedPem("pw"), KeyPassword = "pw" });

        await key.ValidateAsync(Sign(signer), "client-1", Audience);
    }

    [Fact]
    public void EncryptedPem_WithoutPassword_Fails()
    {
        using var key = TestSigningKey.Rsa();

        var ex = Assert.Throws<InvalidOperationException>(() => Load(new PrivateKeyJwtOptions { Key = key.EncryptedPem("pw") }));
        Assert.Contains("KeyPassword", ex.Message);
    }

    [Fact]
    public void EncryptedPem_WrongPassword_Fails()
    {
        using var key = TestSigningKey.Rsa();

        var ex = Assert.Throws<InvalidOperationException>(
            () => Load(new PrivateKeyJwtOptions { Key = key.EncryptedPem("pw"), KeyPassword = "wrong" }));
        Assert.Contains("could not be decrypted", ex.Message);
    }

    [Theory]
    [InlineData("rsa")]
    [InlineData("ec")]
    public async Task Pkcs12File_WithPassword_LoadsKeyAndThumbprints(string keyType)
    {
        // Entra certificate credentials and Keycloak "Generate new keys" (PKCS12) both yield a .pfx/.p12.
        using var key = keyType == "rsa" ? TestSigningKey.Rsa() : TestSigningKey.Ec(ECCurve.NamedCurves.nistP256);
        var path = key.WriteTempFile(key.Pfx("pfx-pw"));
        var signer = Load(new PrivateKeyJwtOptions { KeyFile = path, KeyPassword = "pfx-pw" });

        var jwt = await key.ValidateAsync(Sign(signer), "client-1", Audience);
        Assert.Equal(key.X5t, jwt.GetHeaderValue<string>("x5t"));
        Assert.Equal(key.X5tS256, jwt.GetHeaderValue<string>("x5t#S256"));
    }

    [Fact]
    public void Pkcs12File_WrongPassword_Fails()
    {
        using var key = TestSigningKey.Rsa();
        var path = key.WriteTempFile(key.Pfx("pfx-pw"));

        var ex = Assert.Throws<InvalidOperationException>(
            () => Load(new PrivateKeyJwtOptions { KeyFile = path, KeyPassword = "wrong" }));
        Assert.Contains("KeyPassword is wrong", ex.Message);
    }

    [Fact]
    public async Task PemFile_IsDetectedFromContent()
    {
        using var key = TestSigningKey.Rsa();
        var path = key.WriteTempFile(key.PemWithCertificate);
        var signer = Load(new PrivateKeyJwtOptions { KeyFile = path });

        var jwt = await key.ValidateAsync(Sign(signer), "client-1", Audience);
        Assert.Equal(key.X5t, jwt.GetHeaderValue<string>("x5t"));
    }

    [Fact]
    public void KeyFileAndKey_BothSet_Fails()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => Load(new PrivateKeyJwtOptions { KeyFile = "/x.pem", Key = "-----BEGIN PRIVATE KEY-----" }));
        Assert.Contains("mutually exclusive", ex.Message);
    }

    [Fact]
    public void InlineKey_NotJsonOrPem_Fails()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Load(new PrivateKeyJwtOptions { Key = "c2VjcmV0" }));
        Assert.Contains("Zitadel key file (JSON) or a PEM", ex.Message);
    }

    [Fact]
    public void PublicKeyOnlyPem_Fails()
    {
        using var key = TestSigningKey.Rsa();

        var ex = Assert.Throws<InvalidOperationException>(
            () => Load(new PrivateKeyJwtOptions { Key = key.Key.ExportSubjectPublicKeyInfoPem() }));
        Assert.Contains("no private key", ex.Message);
    }

    [Fact]
    public void ResolveClientId_ZitadelKeyFile_RejectsMismatch_AllowsEmptyOrEqual()
    {
        using var key = TestSigningKey.Rsa();
        var signer = Load(new PrivateKeyJwtOptions { Key = key.ZitadelKeyFile(clientId: "app@project") });

        Assert.Equal("app@project", signer.ResolveClientId(null, "X.ClientId"));
        Assert.Equal("app@project", signer.ResolveClientId("app@project", "X.ClientId"));
        var ex = Assert.Throws<InvalidOperationException>(() => signer.ResolveClientId("other", "X.ClientId"));
        Assert.Contains("does not match", ex.Message);
    }

    [Fact]
    public void ResolveClientId_PemKey_RequiresConfiguredClientId()
    {
        using var key = TestSigningKey.Rsa();
        var signer = Load(new PrivateKeyJwtOptions { Key = key.Pkcs8Pem });

        Assert.Equal("configured", signer.ResolveClientId("configured", "X.ClientId"));
        var ex = Assert.Throws<InvalidOperationException>(() => signer.ResolveClientId("", "X.ClientId"));
        Assert.Contains("X.ClientId is required", ex.Message);
    }

    [Fact]
    public void Assertion_HasRequiredClaims_AndShortLifetime()
    {
        using var key = TestSigningKey.Rsa();
        var signer = Load(new PrivateKeyJwtOptions { Key = key.Pkcs8Pem });
        var now = DateTimeOffset.UtcNow;

        var first = new JsonWebToken(signer.CreateAssertion("client-1", Audience, now));
        var second = new JsonWebToken(signer.CreateAssertion("client-1", Audience, now));

        Assert.Equal("client-1", first.Issuer);
        Assert.Equal("client-1", first.Subject);
        Assert.Equal([Audience], first.Audiences);
        Assert.Equal("JWT", first.Typ);
        Assert.Equal(now.ToUnixTimeSeconds(), new DateTimeOffset(first.IssuedAt).ToUnixTimeSeconds());
        Assert.Equal(TimeSpan.FromMinutes(1), first.ValidTo - first.IssuedAt);
        // RFC 7523 §3: jti must be unique so the IdP can reject replays.
        Assert.NotEqual(first.Id, second.Id);
    }
}
