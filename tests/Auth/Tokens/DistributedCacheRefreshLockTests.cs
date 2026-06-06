using System.Collections.Concurrent;

using b17s.Porta.Auth.Tokens;

using Microsoft.Extensions.Caching.Distributed;

namespace b17s.Porta.Tests.Auth.Tokens;

public class DistributedCacheRefreshLockTests
{
    [Fact]
    public async Task AcquireAsync_OnEmptyCache_ReturnsAcquiredHandle()
    {
        var cache = new InMemoryDistributedCache();
        var sut = new DistributedCacheRefreshLock(cache);

        await using var handle = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);

        Assert.True(handle.Acquired);
    }

    [Fact]
    public async Task AcquireAsync_WhileHeld_BlocksUntilTimeout()
    {
        var cache = new InMemoryDistributedCache();
        var sut = new DistributedCacheRefreshLock(cache);

        var first = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(first.Acquired);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var second = await sut.AcquireAsync("user-1", TimeSpan.FromMilliseconds(250), TestContext.Current.CancellationToken);
        sw.Stop();

        Assert.False(second.Acquired);
        Assert.True(sw.ElapsedMilliseconds >= 200, $"expected wait near 250ms, got {sw.ElapsedMilliseconds}ms");

        await first.DisposeAsync();
    }

    [Fact]
    public async Task AcquireAsync_AfterRelease_SecondCallerSucceeds()
    {
        var cache = new InMemoryDistributedCache();
        var sut = new DistributedCacheRefreshLock(cache);

        var first = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        await first.DisposeAsync();

        await using var second = await sut.AcquireAsync("user-1", TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);

        Assert.True(second.Acquired);
    }

    [Fact]
    public async Task DifferentLockKeys_DoNotInterfere()
    {
        var cache = new InMemoryDistributedCache();
        var sut = new DistributedCacheRefreshLock(cache);

        await using var a = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        await using var b = await sut.AcquireAsync("user-2", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);

        Assert.True(a.Acquired);
        Assert.True(b.Acquired);
    }

    [Fact]
    public async Task Release_DoesNotEvictAnotherHoldersLock()
    {
        // Compare-and-delete: a stale disposer must not clear out a lock now held
        // by someone else (would happen if release just blindly Remove'd the key).
        var cache = new InMemoryDistributedCache();
        var sut = new DistributedCacheRefreshLock(cache);

        var first = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(first.Acquired);

        // Forcibly evict the cache entry, simulating TTL expiry mid-flight.
        await cache.RemoveAsync("porta:refresh-lock:user-1", TestContext.Current.CancellationToken);

        var second = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(second.Acquired);

        // First disposer must NOT clear the second holder's slot.
        await first.DisposeAsync();

        var raw = await cache.GetAsync("porta:refresh-lock:user-1", TestContext.Current.CancellationToken);
        Assert.NotNull(raw);

        await second.DisposeAsync();
    }

    private sealed class InMemoryDistributedCache : IDistributedCache
    {
        private readonly ConcurrentDictionary<string, byte[]> _store = new();

        public byte[]? Get(string key) => _store.TryGetValue(key, out var v) ? v : null;
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult(Get(key));
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) => _store.TryRemove(key, out _);
        public Task RemoveAsync(string key, CancellationToken token = default) { Remove(key); return Task.CompletedTask; }
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _store[key] = value;
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Set(key, value, options);
            return Task.CompletedTask;
        }
    }
}
