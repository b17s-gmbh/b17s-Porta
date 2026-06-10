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

    [Fact]
    public async Task AcquireAsync_WhenCacheThrows_ReturnsNotAcquiredInsteadOfThrowing()
    {
        // Cache outage (Redis down) must degrade per the IRefreshLock contract -
        // "lock unavailable -> serve the stale token" - not escape into the caller
        // and fail an otherwise-valid session.
        var cache = new InMemoryDistributedCache { ThrowOnAccess = true };
        var sut = new DistributedCacheRefreshLock(cache);

        await using var handle = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);

        Assert.False(handle.Acquired);
    }

    [Fact]
    public async Task AcquireAsync_WhenCanceled_PropagatesCancellation()
    {
        // Cooperative cancellation (request abort, shutdown) must keep propagating;
        // only infrastructure faults are converted to a not-acquired handle.
        var cache = new InMemoryDistributedCache();
        var sut = new DistributedCacheRefreshLock(cache);
        using var cts = new CancellationTokenSource();
        cache.OnAccess = () => cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), cts.Token));
    }

    [Fact]
    public async Task AcquireAsync_CanceledBetweenSetAndVerify_ReleasesOrphanedLock()
    {
        // If cancellation hits after the SET landed but before the verify read, the
        // abandoned entry must be compare-and-deleted - otherwise it blocks every
        // other replica for the full lock TTL (30s).
        var cache = new InMemoryDistributedCache();
        var sut = new DistributedCacheRefreshLock(cache);
        using var cts = new CancellationTokenSource();
        var accesses = 0;
        cache.OnAccess = () =>
        {
            // Access 1: existence GET. Access 2: SET. Access 3: verify GET -> cancel.
            if (++accesses == 3)
            {
                cts.Cancel();
            }
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), cts.Token));

        cache.OnAccess = null;
        var raw = await cache.GetAsync("porta:refresh-lock:user-1", TestContext.Current.CancellationToken);
        Assert.Null(raw);
    }

    // TTL expiry semantics: the 30s lock TTL bounds how long a crashed acquirer
    // (one that never disposes its handle) can block other replicas. Driven by a
    // fake clock shared between the lock and the cache so no real time passes.
    // A zero acquire timeout makes the waiter probe exactly once and give up,
    // keeping the test off the real-time backoff path.

    [Fact]
    public async Task AcquireAsync_HolderCrashed_LockStillHeldBeforeTtlExpires()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero));
        var cache = new InMemoryDistributedCache { Clock = clock };
        var sut = new DistributedCacheRefreshLock(cache, clock);

        var crashed = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(crashed.Acquired);
        // Never disposed - simulates a holder that died mid-refresh.

        clock.Advance(TimeSpan.FromSeconds(29));
        var contender = await sut.AcquireAsync("user-1", TimeSpan.Zero, TestContext.Current.CancellationToken);

        Assert.False(contender.Acquired);
    }

    [Fact]
    public async Task AcquireAsync_HolderCrashed_LockSelfEvictsAfterTtl()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero));
        var cache = new InMemoryDistributedCache { Clock = clock };
        var sut = new DistributedCacheRefreshLock(cache, clock);

        var crashed = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(crashed.Acquired);

        clock.Advance(TimeSpan.FromSeconds(31));
        await using var contender = await sut.AcquireAsync("user-1", TimeSpan.Zero, TestContext.Current.CancellationToken);

        Assert.True(contender.Acquired);
    }

    [Fact]
    public async Task DisposeAsync_AfterTtlExpiryAndReacquire_DoesNotEvictNewHoldersLock()
    {
        // The compare-and-delete release must hold under natural TTL expiry, not just
        // manual eviction: a delayed disposer whose entry expired and was re-acquired
        // by another replica must leave the new holder's lock in place.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero));
        var cache = new InMemoryDistributedCache { Clock = clock };
        var sut = new DistributedCacheRefreshLock(cache, clock);

        var stale = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(stale.Acquired);

        clock.Advance(TimeSpan.FromSeconds(31));
        var current = await sut.AcquireAsync("user-1", TimeSpan.Zero, TestContext.Current.CancellationToken);
        Assert.True(current.Acquired);

        await stale.DisposeAsync();

        var raw = await cache.GetAsync("porta:refresh-lock:user-1", TestContext.Current.CancellationToken);
        Assert.NotNull(raw);

        await current.DisposeAsync();
    }

    [Fact]
    public async Task DisposeAsync_WhenCacheThrowsOnRelease_DoesNotThrow()
    {
        // A cache outage between acquire and release must not surface through the
        // handle's await-using disposal; the TTL evicts the orphaned lock entry.
        var cache = new InMemoryDistributedCache();
        var sut = new DistributedCacheRefreshLock(cache);

        var handle = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(handle.Acquired);

        cache.ThrowOnAccess = true;
        await handle.DisposeAsync();
    }

    private sealed class InMemoryDistributedCache : IDistributedCache
    {
        private readonly ConcurrentDictionary<string, (byte[] Value, DateTimeOffset? ExpiresAt)> _store = new();

        public bool ThrowOnAccess { get; set; }
        public Action? OnAccess { get; set; }

        // Clock used for expiry checks; share the lock's FakeTimeProvider so TTL
        // expiry and the acquire deadline advance together.
        public TimeProvider Clock { get; set; } = TimeProvider.System;

        public byte[]? Get(string key)
        {
            if (!_store.TryGetValue(key, out var entry))
            {
                return null;
            }
            if (entry.ExpiresAt is { } expiresAt && Clock.GetUtcNow() >= expiresAt)
            {
                _store.TryRemove(key, out _);
                return null;
            }
            return entry.Value;
        }
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            Touch(token);
            return Task.FromResult(Get(key));
        }
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) => _store.TryRemove(key, out _);
        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            Touch(token);
            Remove(key);
            return Task.CompletedTask;
        }
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            // Honor the TTL options the SUT passes (AbsoluteExpirationRelativeToNow for the
            // lock TTL); a fake that ignores them silently un-tests expiry semantics.
            DateTimeOffset? expiresAt = options.AbsoluteExpirationRelativeToNow is { } relative
                ? Clock.GetUtcNow() + relative
                : options.AbsoluteExpiration;
            _store[key] = (value, expiresAt);
        }
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Touch(token);
            Set(key, value, options);
            return Task.CompletedTask;
        }

        private void Touch(CancellationToken token)
        {
            OnAccess?.Invoke();
            token.ThrowIfCancellationRequested();
            if (ThrowOnAccess)
            {
                throw new InvalidOperationException("cache unavailable");
            }
        }
    }

    /// <summary>
    /// Minimal mutable TimeProvider that lets tests advance the clock without sleeping.
    /// Mirrors the pattern used by RefreshLockRegistryTests.
    /// </summary>
    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now = _now.Add(by);
    }
}
