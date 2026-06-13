using System.Text;
using System.Text.Json;

using b17s.Porta.Auth.Sessions;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace b17s.Porta.Tests.Auth.Sessions;

public sealed class SessionTokenStorageTests
{
    [Fact]
    public async Task SetTokenAsync_GetTokenAsync_RoundTripsValue_WithoutProtector()
    {
        var ctx = NewHttpContext();
        var sut = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance, dataProtectionProvider: null);

        await sut.SetTokenAsync(ctx, "key", "the-value");
        var read = await sut.GetTokenAsync(ctx, "key");

        Assert.Equal("the-value", read);
    }

    [Fact]
    public async Task SetTokenAsync_GetTokenAsync_RoundTripsValue_WithProtector()
    {
        // Data-Protection round-trip: ciphertext is what lands in session storage,
        // plaintext is what comes back to the caller.
        var ctx = NewHttpContext();
        var protector = new EphemeralDataProtectionProvider();
        var sut = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance, protector);

        await sut.SetTokenAsync(ctx, "key", "secret-token");

        // Stored bytes are not the plaintext.
        var stored = ((FakeSession)ctx.Session).RawString("key");
        Assert.NotEqual("secret-token", stored);

        var read = await sut.GetTokenAsync(ctx, "key");
        Assert.Equal("secret-token", read);
    }

    [Fact]
    public async Task GetTokenAsync_DecryptionFails_ReturnsNull_WithoutThrowing()
    {
        // Defense against rotated/lost DP keys: stored ciphertext that can no longer be
        // unprotected should look like "no token" to the caller, not throw - otherwise
        // every request after a key rotation would 500.
        var ctx = NewHttpContext();
        var protectorA = new EphemeralDataProtectionProvider();
        var protectorB = new EphemeralDataProtectionProvider(); // different keys

        var writer = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance, protectorA);
        await writer.SetTokenAsync(ctx, "key", "secret-token");

        var reader = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance, protectorB);
        var read = await reader.GetTokenAsync(ctx, "key");

        Assert.Null(read);
    }

    [Fact]
    public async Task GetTokenAsync_MissingKey_ReturnsNull()
    {
        var ctx = NewHttpContext();
        var sut = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance);

        var read = await sut.GetTokenAsync(ctx, "missing");

        Assert.Null(read);
    }

    [Fact]
    public async Task RemoveTokenAsync_RemovesValue()
    {
        var ctx = NewHttpContext();
        var sut = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance);
        await sut.SetTokenAsync(ctx, "key", "v");

        await sut.RemoveTokenAsync(ctx, "key");

        Assert.Null(await sut.GetTokenAsync(ctx, "key"));
    }

    [Fact]
    public async Task SetObjectAsync_GetObjectAsync_RoundTripsObject_WithProtector()
    {
        var ctx = NewHttpContext();
        var protector = new EphemeralDataProtectionProvider();
        var sut = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance, protector);
        var payload = new Payload { Id = 42, Name = "ada" };

        await sut.SetObjectAsync(ctx, "obj", payload);
        var read = await sut.GetObjectAsync<Payload>(ctx, "obj");

        Assert.NotNull(read);
        Assert.Equal(42, read!.Id);
        Assert.Equal("ada", read.Name);
    }

    [Fact]
    public async Task SetObjectAsync_StoresEncryptedJson_NotPlainJson()
    {
        // The bytes-at-rest test for SetObjectAsync: stored value must not be plain JSON
        // when a protector is wired. If it is, encryption silently regressed.
        var ctx = NewHttpContext();
        var protector = new EphemeralDataProtectionProvider();
        var sut = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance, protector);

        await sut.SetObjectAsync(ctx, "obj", new Payload { Id = 1, Name = "x" });

        var stored = ((FakeSession)ctx.Session).RawString("obj");
        Assert.NotNull(stored);
        Assert.DoesNotContain("\"id\"", stored!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\"name\"", stored, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetObjectAsync_DecryptionFails_ReturnsNull()
    {
        // Same DP-rotation defense as for strings, but on the typed-object path.
        var ctx = NewHttpContext();
        var protectorA = new EphemeralDataProtectionProvider();
        var protectorB = new EphemeralDataProtectionProvider();

        var writer = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance, protectorA);
        await writer.SetObjectAsync(ctx, "obj", new Payload { Id = 1, Name = "x" });

        var reader = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance, protectorB);
        var read = await reader.GetObjectAsync<Payload>(ctx, "obj");

        Assert.Null(read);
    }

    [Fact]
    public async Task GetObjectAsync_MissingKey_ReturnsNull()
    {
        var ctx = NewHttpContext();
        var sut = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance);

        var read = await sut.GetObjectAsync<Payload>(ctx, "missing");

        Assert.Null(read);
    }

    [Fact]
    public async Task GetObjectAsync_MalformedJson_ReturnsNull()
    {
        // Defensive parsing: a session entry that doesn't deserialize must not surface
        // as a 500 - return null and let the caller treat as "no value".
        var ctx = NewHttpContext();
        var sut = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance);
        ((FakeSession)ctx.Session).SetRawString("obj", "{ not valid json");

        var read = await sut.GetObjectAsync<Payload>(ctx, "obj");

        Assert.Null(read);
    }

    [Fact]
    public async Task ClearAllAsync_RemovesEverything()
    {
        var ctx = NewHttpContext();
        var sut = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance);
        await sut.SetTokenAsync(ctx, "k1", "v1");
        await sut.SetTokenAsync(ctx, "k2", "v2");

        var ok = await sut.ClearAllAsync(ctx);

        Assert.True(ok);
        Assert.Null(await sut.GetTokenAsync(ctx, "k1"));
        Assert.Null(await sut.GetTokenAsync(ctx, "k2"));
    }

    [Fact]
    public async Task RemoveObjectAsync_DelegatesToRemoveToken()
    {
        var ctx = NewHttpContext();
        var sut = new SessionTokenStorage(NullLogger<SessionTokenStorage>.Instance);
        await sut.SetObjectAsync(ctx, "obj", new Payload { Id = 1, Name = "x" });

        await sut.RemoveObjectAsync(ctx, "obj");

        Assert.Null(await sut.GetObjectAsync<Payload>(ctx, "obj"));
    }

    private static HttpContext NewHttpContext()
    {
        return new DefaultHttpContext { Session = new FakeSession() };
    }

    private sealed class Payload
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";
    }

    /// <summary>
    /// In-memory ISession sufficient for token-storage tests. Stores string entries
    /// verbatim so we can also inspect the bytes-at-rest after encryption.
    /// </summary>
    private sealed class FakeSession : ISession
    {
        private readonly Dictionary<string, byte[]> _store = new();

        public bool IsAvailable => true;
        public string Id { get; } = Guid.NewGuid().ToString();
        public IEnumerable<string> Keys => _store.Keys;

        public void Clear() => _store.Clear();
        public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public void Remove(string key) => _store.Remove(key);

        public void Set(string key, byte[] value) => _store[key] = value;

        public bool TryGetValue(string key, out byte[] value)
        {
            if (_store.TryGetValue(key, out var found))
            {
                value = found;
                return true;
            }
            value = Array.Empty<byte>();
            return false;
        }

        public string? RawString(string key) =>
            _store.TryGetValue(key, out var bytes) ? Encoding.UTF8.GetString(bytes) : null;

        public void SetRawString(string key, string value) =>
            _store[key] = Encoding.UTF8.GetBytes(value);
    }
}
