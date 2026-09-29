using b17s.Porta.Auth.Tokens;
using b17s.Porta.Tests.Fixtures;

namespace b17s.Porta.Tests.Auth.Tokens;

/// <summary>
/// Tests for <see cref="ClientAssertionSignerCache"/>: key material is parsed once per configured
/// value, a changed configuration replaces the slot's entry (bounded by the number of clients, not
/// by the number of reloads), and caches are per instance rather than process-wide.
/// </summary>
public sealed class ClientAssertionSignerCacheTests
{
    [Fact]
    public void SameSlotAndOptions_ReturnsCachedSigner()
    {
        using var key = TestSigningKey.Rsa();
        var cache = new ClientAssertionSignerCache();

        var first = cache.GetOrLoad("slot", new PrivateKeyJwtOptions { Key = key.Pkcs8Pem, KeyId = "a" });
        var second = cache.GetOrLoad("slot", new PrivateKeyJwtOptions { Key = key.Pkcs8Pem, KeyId = "a" });

        Assert.Same(first, second);
    }

    [Fact]
    public void ChangedOptions_ReloadAndReplaceTheSlotEntry()
    {
        using var key = TestSigningKey.Rsa();
        var cache = new ClientAssertionSignerCache();
        var v1 = new PrivateKeyJwtOptions { Key = key.Pkcs8Pem, KeyId = "v1" };
        var v2 = new PrivateKeyJwtOptions { Key = key.Pkcs8Pem, KeyId = "v2" };

        var first = cache.GetOrLoad("slot", v1);
        var reloaded = cache.GetOrLoad("slot", v2);
        // v1 was replaced, not kept alongside v2: switching back loads again.
        var back = cache.GetOrLoad("slot", v1);

        Assert.NotSame(first, reloaded);
        Assert.NotSame(first, back);
    }

    [Fact]
    public void FileKey_IsReadOnce_UntilOptionsChange()
    {
        // The request path must not re-read the key file per call; deleting the file after the
        // first load proves the cached signer is served.
        using var key = TestSigningKey.Rsa();
        var path = key.WriteTempFile(key.Pkcs8Pem);
        var cache = new ClientAssertionSignerCache();
        var options = new PrivateKeyJwtOptions { KeyFile = path };

        var first = cache.GetOrLoad("slot", options);
        File.Delete(path);
        var second = cache.GetOrLoad("slot", options);

        Assert.Same(first, second);
    }

    [Fact]
    public void Slots_AreIndependent()
    {
        using var key = TestSigningKey.Rsa();
        var cache = new ClientAssertionSignerCache();
        var options = new PrivateKeyJwtOptions { Key = key.Pkcs8Pem };

        var a = cache.GetOrLoad("a", options);
        var b = cache.GetOrLoad("b", options);

        Assert.NotSame(a, b);
        Assert.Same(a, cache.GetOrLoad("a", options));
    }

    [Fact]
    public void Instances_DoNotShareEntries()
    {
        using var key = TestSigningKey.Rsa();
        var options = new PrivateKeyJwtOptions { Key = key.Pkcs8Pem };

        Assert.NotSame(
            new ClientAssertionSignerCache().GetOrLoad("slot", options),
            new ClientAssertionSignerCache().GetOrLoad("slot", options));
    }

    [Fact]
    public void LoadFailure_IsNotCached_AndDoesNotServeThePreviousKey()
    {
        using var key = TestSigningKey.Rsa();
        var cache = new ClientAssertionSignerCache();
        cache.GetOrLoad("slot", new PrivateKeyJwtOptions { Key = key.Pkcs8Pem });
        var missing = new PrivateKeyJwtOptions { KeyFile = Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.pem") };

        Assert.Throws<InvalidOperationException>(() => cache.GetOrLoad("slot", missing));
        // Still failing on the next call: the failure is retried, and the old key is not served.
        Assert.Throws<InvalidOperationException>(() => cache.GetOrLoad("slot", missing));
    }
}
