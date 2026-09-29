using System.Buffers.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Signs <c>private_key_jwt</c> client assertions (RFC 7523 §2.2 / §3) from the key material in
/// <see cref="PrivateKeyJwtOptions"/>. Immutable once loaded; consumers hold instances in a
/// <see cref="ClientAssertionSignerCache"/> so key material is parsed once, not per request.
/// </summary>
internal sealed class ClientAssertionSigner
{
    /// <summary><c>client_assertion_type</c> value for a JWT client assertion (RFC 7523 §2.2).</summary>
    public const string ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    // Short-lived: a new assertion (fresh jti) is minted for every token/introspection request, so the
    // lifetime only needs to cover transit plus modest clock skew between BFF and IdP.
    private static readonly TimeSpan AssertionLifetime = TimeSpan.FromMinutes(1);

    private static readonly string[] RsaAlgorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];

    private readonly AsymmetricAlgorithm _key;
    // RSA/ECDsa instances are not documented as thread-safe; signing is rare (results are cached
    // upstream) and fast, so serialize it rather than rely on platform behavior.
    private readonly Lock _signLock = new();
    private readonly string? _keyId;
    private readonly string? _x5t;
    private readonly string? _x5tS256;

    private ClientAssertionSigner(
        AsymmetricAlgorithm key, string algorithm, string? keyId, byte[]? certificateDer, string? keyFileClientId)
    {
        _key = key;
        Algorithm = algorithm;
        _keyId = keyId;
        KeyFileClientId = keyFileClientId;
        if (certificateDer is not null)
        {
            _x5t = Base64Url.EncodeToString(SHA1.HashData(certificateDer));
            _x5tS256 = Base64Url.EncodeToString(SHA256.HashData(certificateDer));
        }
    }

    /// <summary>The JWS algorithm the assertions are signed with.</summary>
    public string Algorithm { get; }

    /// <summary>The client id embedded in a Zitadel key file; null for PEM / PKCS#12 key material.</summary>
    public string? KeyFileClientId { get; }

    /// <summary>True when the key material carries a certificate, so assertions include <c>x5t</c> / <c>x5t#S256</c>.</summary>
    public bool HasCertificate => _x5t is not null;

    /// <summary>
    /// Resolves the client id for an assertion: the Zitadel key file's client id when present
    /// (<paramref name="configuredClientId"/> must then be empty or equal), otherwise the configured one.
    /// </summary>
    /// <exception cref="InvalidOperationException">No client id is available, or it conflicts with the key file.</exception>
    public string ResolveClientId(string? configuredClientId, string clientIdSetting)
    {
        if (KeyFileClientId is not null)
        {
            if (!string.IsNullOrEmpty(configuredClientId)
                && !string.Equals(configuredClientId, KeyFileClientId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"{clientIdSetting} '{configuredClientId}' does not match the clientId '{KeyFileClientId}' in the " +
                    $"Zitadel key file. Leave {clientIdSetting} empty or set it to the key file's clientId.");
            }

            return KeyFileClientId;
        }

        if (string.IsNullOrEmpty(configuredClientId))
        {
            throw new InvalidOperationException(
                $"{clientIdSetting} is required with private_key_jwt unless the key is a Zitadel key file " +
                "(which carries its own clientId).");
        }

        return configuredClientId;
    }

    /// <summary>
    /// Mints a signed client assertion: <c>iss</c> = <c>sub</c> = <paramref name="clientId"/>,
    /// <c>aud</c> = <paramref name="audience"/>, a unique <c>jti</c>, and a short <c>exp</c>.
    /// </summary>
    public string CreateAssertion(string clientId, string audience, DateTimeOffset now)
    {
        var header = WriteJson(w =>
        {
            w.WriteString("alg", Algorithm);
            w.WriteString("typ", "JWT");
            if (!string.IsNullOrEmpty(_keyId)) w.WriteString("kid", _keyId);
            if (_x5t is not null) w.WriteString("x5t", _x5t);
            if (_x5tS256 is not null) w.WriteString("x5t#S256", _x5tS256);
        });

        var issuedAt = now.ToUnixTimeSeconds();
        var payload = WriteJson(w =>
        {
            w.WriteString("iss", clientId);
            w.WriteString("sub", clientId);
            w.WriteString("aud", audience);
            w.WriteString("jti", Guid.NewGuid().ToString("N"));
            w.WriteNumber("iat", issuedAt);
            w.WriteNumber("nbf", issuedAt);
            w.WriteNumber("exp", issuedAt + (long)AssertionLifetime.TotalSeconds);
        });

        var signingInput = $"{Base64Url.EncodeToString(header)}.{Base64Url.EncodeToString(payload)}";
        var data = Encoding.ASCII.GetBytes(signingInput);
        var hash = Algorithm[^3..] switch
        {
            "384" => HashAlgorithmName.SHA384,
            "512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };

        byte[] signature;
        lock (_signLock)
        {
            signature = _key switch
            {
                RSA rsa => rsa.SignData(data, hash,
                    Algorithm.StartsWith("PS", StringComparison.Ordinal) ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1),
                // .NET's default ECDSA signature format is IEEE P1363 (r || s), which is what JWS requires.
                ECDsa ecdsa => ecdsa.SignData(data, hash),
                _ => throw new InvalidOperationException("Unsupported private_key_jwt key type."),
            };
        }

        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>
    /// Loads the key material configured in <paramref name="options"/>. Reads the key file on every call;
    /// use <see cref="ClientAssertionSignerCache"/> on request paths.
    /// </summary>
    /// <exception cref="InvalidOperationException">The key material is missing, unreadable, or invalid.</exception>
    public static ClientAssertionSigner Load(PrivateKeyJwtOptions options)
    {
        var hasFile = !string.IsNullOrEmpty(options.KeyFile);
        var hasInline = !string.IsNullOrEmpty(options.Key);
        if (hasFile == hasInline)
        {
            throw new InvalidOperationException(hasFile
                ? "KeyFile and Key are mutually exclusive."
                : "Either KeyFile or Key is required.");
        }

        if (hasInline)
        {
            return LoadText(options.Key!, options)
                ?? throw new InvalidOperationException(
                    "Key must contain a Zitadel key file (JSON) or a PEM private key. Use KeyFile for PKCS#12.");
        }

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(options.KeyFile!);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new InvalidOperationException($"KeyFile '{options.KeyFile}' could not be read: {ex.Message}", ex);
        }

        return LoadText(Encoding.UTF8.GetString(bytes), options) ?? LoadPkcs12(bytes, options);
    }

    // Returns null when the content is neither JSON nor PEM (the caller then tries PKCS#12).
    private static ClientAssertionSigner? LoadText(string content, PrivateKeyJwtOptions options)
    {
        var trimmed = content.TrimStart('﻿', ' ', '\t', '\r', '\n');
        if (trimmed.StartsWith('{'))
            return LoadZitadelKeyFile(trimmed, options);
        if (trimmed.Contains("-----BEGIN", StringComparison.Ordinal))
            return LoadPem(trimmed, options);
        return null;
    }

    private static ClientAssertionSigner LoadZitadelKeyFile(string json, PrivateKeyJwtOptions options)
    {
        ZitadelApplicationKey? keyFile;
        try
        {
            keyFile = JsonSerializer.Deserialize<ZitadelApplicationKey>(json);
        }
        catch (JsonException ex)
        {
            // Do not surface ex.Message verbatim: it can quote fragments of the key material.
            throw new InvalidOperationException($"Zitadel key file is not valid JSON (line {ex.LineNumber}).");
        }

        if (keyFile is null)
            throw new InvalidOperationException("Zitadel key file is empty.");
        if (!string.Equals(keyFile.Type, "application", StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"Zitadel key file must be an application key (\"type\": \"application\"). Got: '{keyFile.Type}'.");
        if (string.IsNullOrWhiteSpace(keyFile.KeyId))
            throw new InvalidOperationException("Zitadel key file is missing \"keyId\".");
        if (string.IsNullOrWhiteSpace(keyFile.ClientId))
            throw new InvalidOperationException("Zitadel key file is missing \"clientId\".");
        if (string.IsNullOrWhiteSpace(keyFile.Key))
            throw new InvalidOperationException("Zitadel key file is missing \"key\".");

        var key = ImportPemPrivateKey(keyFile.Key, password: null);
        return Create(key, options, keyId: options.KeyId ?? keyFile.KeyId, certificateDer: null, keyFile.ClientId);
    }

    private static ClientAssertionSigner LoadPem(string pem, PrivateKeyJwtOptions options)
    {
        var key = ImportPemPrivateKey(pem, options.KeyPassword);
        try
        {
            // A PEM bundle may carry the certificate (and chain) next to the key. Use the one
            // matching the key: a mismatched certificate would send thumbprints the IdP rejects.
            var certificates = FindPemBlocks(pem, "CERTIFICATE");
            byte[]? certificateDer = null;
            if (certificates.Count > 0)
            {
                var publicKey = key.ExportSubjectPublicKeyInfo();
                certificateDer = certificates.FirstOrDefault(der => CertificateMatches(der, publicKey))
                    ?? throw new InvalidOperationException("No CERTIFICATE in the PEM matches its private key.");
            }

            return Create(key, options, options.KeyId, certificateDer, keyFileClientId: null);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private static ClientAssertionSigner LoadPkcs12(byte[] bytes, PrivateKeyJwtOptions options)
    {
        X509Certificate2 certificate;
        try
        {
            // Ephemeral keys avoid writing the private key to the user profile / machine key store
            // on Windows; macOS does not support them.
            var flags = OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;
            certificate = X509CertificateLoader.LoadPkcs12(bytes, options.KeyPassword, flags);
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException(
                "KeyFile is not a Zitadel key file, PEM, or PKCS#12 file, or the KeyPassword is wrong.");
        }

        using (certificate)
        {
            AsymmetricAlgorithm key = (AsymmetricAlgorithm?)certificate.GetRSAPrivateKey()
                ?? certificate.GetECDsaPrivateKey()
                ?? throw new InvalidOperationException("The PKCS#12 file contains no RSA or EC private key.");
            try
            {
                return Create(key, options, options.KeyId, certificate.RawData, keyFileClientId: null);
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }
    }

    private static ClientAssertionSigner Create(
        AsymmetricAlgorithm key, PrivateKeyJwtOptions options, string? keyId, byte[]? certificateDer, string? keyFileClientId)
    {
        string algorithm;
        if (key is RSA rsa)
        {
            if (rsa.KeySize < 2048)
                throw new InvalidOperationException($"RSA key must be at least 2048 bits. Got: {rsa.KeySize}.");

            algorithm = options.Algorithm ?? "RS256";
            if (!RsaAlgorithms.Contains(algorithm, StringComparer.Ordinal))
                throw new InvalidOperationException(
                    $"Algorithm '{algorithm}' is not valid for an RSA key. Use one of: {string.Join(", ", RsaAlgorithms)}.");
        }
        else
        {
            var curveAlgorithm = key.KeySize switch
            {
                256 => "ES256",
                384 => "ES384",
                521 => "ES512",
                _ => throw new InvalidOperationException(
                    $"EC key must use P-256, P-384 or P-521. Got a {key.KeySize}-bit curve."),
            };
            algorithm = options.Algorithm ?? curveAlgorithm;
            if (!string.Equals(algorithm, curveAlgorithm, StringComparison.Ordinal))
                throw new InvalidOperationException(
                    $"Algorithm '{algorithm}' does not match the EC key's curve; use '{curveAlgorithm}'.");
        }

        return new ClientAssertionSigner(key, algorithm, keyId, certificateDer, keyFileClientId);
    }

    private static AsymmetricAlgorithm ImportPemPrivateKey(string pem, string? password)
    {
        if (!pem.Contains("PRIVATE KEY-----", StringComparison.Ordinal))
            throw new InvalidOperationException("PEM contains no private key.");

        var encrypted = pem.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal);
        if (encrypted && string.IsNullOrEmpty(password))
            throw new InvalidOperationException("PEM private key is encrypted; set KeyPassword.");

        // PKCS#8 does not name the algorithm in its PEM label, so try RSA, then EC. Each rejects
        // the other's formats (RSA PRIVATE KEY / EC PRIVATE KEY are ignored by the wrong type).
        foreach (var factory in new Func<AsymmetricAlgorithm>[] { RSA.Create, ECDsa.Create })
        {
            var key = factory();
            try
            {
                if (encrypted)
                    key.ImportFromEncryptedPem(pem, password);
                else
                    key.ImportFromPem(pem);
                return key;
            }
            catch (Exception ex) when (ex is ArgumentException or CryptographicException)
            {
                key.Dispose();
            }
        }

        throw new InvalidOperationException(encrypted
            ? "PEM private key could not be decrypted (wrong KeyPassword?) or is not an RSA/EC key."
            : "PEM private key is not a valid RSA or EC private key.");
    }

    private static List<byte[]> FindPemBlocks(string pem, string label)
    {
        var blocks = new List<byte[]>();
        var remaining = pem.AsSpan();
        while (PemEncoding.TryFind(remaining, out var fields))
        {
            if (remaining[fields.Label].SequenceEqual(label))
                blocks.Add(Convert.FromBase64String(remaining[fields.Base64Data].ToString()));
            remaining = remaining[fields.Location.End..];
        }
        return blocks;
    }

    private static bool CertificateMatches(byte[] certificateDer, byte[] subjectPublicKeyInfo)
    {
        try
        {
            using var certificate = X509CertificateLoader.LoadCertificate(certificateDer);
            return certificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(subjectPublicKeyInfo);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static byte[] WriteJson(Action<Utf8JsonWriter> write)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            write(writer);
            writer.WriteEndObject();
        }
        return buffer.ToArray();
    }

    private sealed class ZitadelApplicationKey
    {
        [JsonPropertyName("type")] public string? Type { get; set; }
        [JsonPropertyName("keyId")] public string? KeyId { get; set; }
        [JsonPropertyName("key")] public string? Key { get; set; }
        [JsonPropertyName("clientId")] public string? ClientId { get; set; }
    }
}
