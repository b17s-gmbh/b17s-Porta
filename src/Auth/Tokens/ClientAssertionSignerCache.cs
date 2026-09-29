using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Holds the loaded <see cref="ClientAssertionSigner"/> for each configured client ("slot", e.g. a
/// configuration path), so key material is parsed once rather than per request. Owned as an instance
/// field by the singleton service that signs, so its lifetime is the service's and nothing is shared
/// process-wide.
/// <para>
/// One entry per slot: when the slot's <see cref="PrivateKeyJwtOptions"/> change (appsettings reload),
/// the key is reloaded and replaces the previous entry, so the cache is bounded by the number of
/// configured clients. Load failures are not cached - the next call retries, and a previously loaded
/// key is never served for changed options.
/// </para>
/// </summary>
internal sealed class ClientAssertionSignerCache
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    /// <summary>
    /// Returns the signer for <paramref name="options"/> under <paramref name="slot"/>, loading it when
    /// the slot is empty or its options changed since the last load.
    /// </summary>
    /// <exception cref="InvalidOperationException">The key material is missing, unreadable, or invalid.</exception>
    public ClientAssertionSigner GetOrLoad(string slot, PrivateKeyJwtOptions options)
    {
        var fingerprint = Fingerprint(options);
        if (_entries.TryGetValue(slot, out var entry) && entry.Fingerprint == fingerprint)
            return entry.Signer;

        // Concurrent first calls may each load once; last writer wins and every result is valid.
        // A replaced signer is not disposed: a request may still be signing with it, and its key
        // handle is released by finalization once unreferenced.
        var signer = ClientAssertionSigner.Load(options);
        _entries[slot] = new Entry(fingerprint, signer);
        return signer;
    }

    // Hash of everything that shapes the signer, so a changed setting loads fresh without the raw
    // key material or password being kept in memory as a dictionary key.
    private static string Fingerprint(PrivateKeyJwtOptions options)
    {
        var material = string.Join('\0',
            options.KeyFile, options.Key, options.KeyPassword, options.KeyId, options.Algorithm);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    private sealed record Entry(string Fingerprint, ClientAssertionSigner Signer);
}
