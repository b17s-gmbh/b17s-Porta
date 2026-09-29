using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace b17s.Porta.Tests.Fixtures;

/// <summary>
/// A freshly generated RSA or EC key with a self-signed certificate, exported in the formats IdPs
/// hand out for <c>private_key_jwt</c>: Zitadel application key file, PEM (PKCS#1 / SEC1 / PKCS#8,
/// plain or encrypted, optionally bundled with the certificate) and PKCS#12. Assertions can be
/// verified against <see cref="ValidateAsync"/>.
/// </summary>
public sealed class TestSigningKey : IDisposable
{
    private readonly List<string> _tempFiles = [];

    private TestSigningKey(AsymmetricAlgorithm key, X509Certificate2 certificate)
    {
        Key = key;
        Certificate = certificate;
    }

    public AsymmetricAlgorithm Key { get; }
    public X509Certificate2 Certificate { get; }

    public static TestSigningKey Rsa(int keySize = 2048)
    {
        var rsa = RSA.Create(keySize);
        var request = new CertificateRequest("CN=porta-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return new TestSigningKey(rsa, request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)));
    }

    public static TestSigningKey Ec(ECCurve curve)
    {
        var ecdsa = ECDsa.Create(curve);
        var request = new CertificateRequest("CN=porta-test", ecdsa, HashAlgorithmName.SHA256);
        return new TestSigningKey(ecdsa, request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)));
    }

    /// <summary>PKCS#1 (<c>RSA PRIVATE KEY</c>) or SEC1 (<c>EC PRIVATE KEY</c>) PEM.</summary>
    public string TraditionalPem => Key switch
    {
        RSA rsa => rsa.ExportRSAPrivateKeyPem(),
        ECDsa ec => ec.ExportECPrivateKeyPem(),
        _ => throw new NotSupportedException(),
    };

    /// <summary>PKCS#8 (<c>PRIVATE KEY</c>) PEM.</summary>
    public string Pkcs8Pem => Key.ExportPkcs8PrivateKeyPem();

    public string EncryptedPem(string password) => Key.ExportEncryptedPkcs8PrivateKeyPem(
        password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10_000));

    /// <summary>PKCS#8 key followed by the matching certificate, as e.g. <c>openssl</c> bundles them.</summary>
    public string PemWithCertificate => Pkcs8Pem + "\n" + Certificate.ExportCertificatePem();

    // CreateSelfSigned already associates the private key with the certificate.
    public byte[] Pfx(string? password) => Certificate.Export(X509ContentType.Pkcs12, password);

    public string ZitadelKeyFile(string clientId = "123456789@porta", string keyId = "key-1", string type = "application") =>
        JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["type"] = type,
            ["keyId"] = keyId,
            // PKCS#1 "BEGIN RSA PRIVATE KEY", exactly what Zitadel emits.
            ["key"] = TraditionalPem,
            ["appId"] = "987654321",
            ["clientId"] = clientId,
        });

    public string X5t => Base64UrlEncoder.Encode(Certificate.GetCertHash());
    public string X5tS256 => Base64UrlEncoder.Encode(Certificate.GetCertHash(HashAlgorithmName.SHA256));

    /// <summary>Writes <paramref name="content"/> to a temp file deleted on <see cref="Dispose"/>.</summary>
    public string WriteTempFile(string content) => WriteTempFile(System.Text.Encoding.UTF8.GetBytes(content));

    public string WriteTempFile(byte[] content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"porta-key-{Guid.NewGuid():N}");
        File.WriteAllBytes(path, content);
        _tempFiles.Add(path);
        return path;
    }

    /// <summary>Validates an assertion's signature against the public key plus iss/aud; lifetime is checked with no skew.</summary>
    public async Task<JsonWebToken> ValidateAsync(string assertion, string issuer, string audience)
    {
        SecurityKey publicKey = Key switch
        {
            RSA rsa => new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: false)),
            ECDsa ec => new ECDsaSecurityKey(ECDsa.Create(ec.ExportParameters(includePrivateParameters: false))),
            _ => throw new NotSupportedException(),
        };

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(assertion, new TokenValidationParameters
        {
            IssuerSigningKey = publicKey,
            ValidIssuer = issuer,
            ValidAudience = audience,
            ClockSkew = TimeSpan.Zero,
        });
        Assert.True(result.IsValid, result.Exception?.Message);
        return (JsonWebToken)result.SecurityToken;
    }

    public void Dispose()
    {
        foreach (var path in _tempFiles)
        {
            try { File.Delete(path); } catch (IOException) { }
        }
        Certificate.Dispose();
        Key.Dispose();
    }
}
