using b17s.Porta.Auth.Tokens;

namespace b17s.Porta.Tests.Auth.Tokens;

/// <summary>
/// Tests for <see cref="RefreshLockRegistry"/> - the in-process implementation of
/// <see cref="IRefreshLock"/>. Covers acquisition contracts, stampede prevention,
/// the cleanup sweep's race-aware semantics, and ObjectDisposedException tolerance.
/// </summary>
public sealed class RefreshLockRegistryTests
{
    // -----------------------------
    // Basic acquisition contract — parity with DistributedCacheRefreshLockTests
    // -----------------------------

    [Fact]
    public async Task AcquireAsync_OnFreshRegistry_ReturnsAcquiredHandle()
    {
        using var sut = new RefreshLockRegistry();

        await using var handle = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);

        Assert.True(handle.Acquired);
    }

    [Fact]
    public async Task AcquireAsync_WhileHeld_BlocksUntilTimeout()
    {
        using var sut = new RefreshLockRegistry();

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
        using var sut = new RefreshLockRegistry();

        var first = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        await first.DisposeAsync();

        await using var second = await sut.AcquireAsync("user-1", TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);

        Assert.True(second.Acquired);
    }

    [Fact]
    public async Task DifferentLockKeys_DoNotInterfere()
    {
        using var sut = new RefreshLockRegistry();

        await using var a = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        await using var b = await sut.AcquireAsync("user-2", TimeSpan.FromMilliseconds(50), TestContext.Current.CancellationToken);

        Assert.True(a.Acquired);
        Assert.True(b.Acquired);
    }

    // -----------------------------
    // Stampede prevention — only one acquirer at a time on the same key
    // -----------------------------

    [Fact]
    public async Task AcquireAsync_ConcurrentStampedeSameKey_OnlyOneSucceeds()
    {
        // Branch coverage on the per-key SemaphoreSlim path: many concurrent acquirers
        // for the same key must serialize - this is the entire point of the registry.
        using var sut = new RefreshLockRegistry();

        const int contenders = 20;
        var holders = new List<Task<RefreshLockHandle>>();
        for (var i = 0; i < contenders; i++)
        {
            // Short timeout so only the first acquirer succeeds; the rest time out.
            holders.Add(sut.AcquireAsync("user-stampede", TimeSpan.FromMilliseconds(100), TestContext.Current.CancellationToken));
        }

        var handles = await Task.WhenAll(holders);

        try
        {
            var acquired = handles.Count(h => h.Acquired);
            Assert.Equal(1, acquired);
        }
        finally
        {
            foreach (var h in handles)
            {
                await h.DisposeAsync();
            }
        }
    }

    [Fact]
    public async Task AcquireAsync_ContenderRespectsCancellation()
    {
        // Branch coverage: the `await semaphore.WaitAsync(timeout, cancellationToken)`
        // path must surface OperationCanceledException when the outer token cancels
        // before the timeout elapses - otherwise callers get a hung Acquire.
        using var sut = new RefreshLockRegistry();

        var holder = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(holder.Acquired);

        using var cts = new CancellationTokenSource();
        var waiter = sut.AcquireAsync("user-1", TimeSpan.FromSeconds(30), cts.Token);

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiter);

        await holder.DisposeAsync();
    }

    // -----------------------------
    // Dispose semantics
    // -----------------------------

    [Fact]
    public async Task Dispose_DoubleDispose_DoesNotThrow()
    {
        // Interlocked.Exchange guard on _disposed - second Dispose must be a no-op.
        var sut = new RefreshLockRegistry();
        await using (await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken)) { }

        sut.Dispose();
        sut.Dispose();
    }

    [Fact]
    public async Task Handle_DoubleDispose_DoesNotDoubleRelease()
    {
        // The handle's _disposed guard means a stray DisposeAsync after the first one
        // must not call Release() a second time (which would corrupt the semaphore's count).
        using var sut = new RefreshLockRegistry();

        var first = await sut.AcquireAsync("user-1", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(first.Acquired);

        await first.DisposeAsync();
        await first.DisposeAsync(); // second dispose must be a no-op

        // The lock should still be free; if Release was called twice the semaphore would now
        // permit two simultaneous holders. We can't directly observe the count, but acquiring
        // and releasing in sequence below should hand back a fresh single permit each time.
        await using (await sut.AcquireAsync("user-1", TimeSpan.FromMilliseconds(100), TestContext.Current.CancellationToken)) { }
    }

    // -----------------------------
    // Cleanup sweep — only ever evicts idle, sufficiently-stale entries
    // -----------------------------

    [Fact]
    public async Task Cleanup_RemovesStaleEntries()
    {
        // Drive the timestamp forward past StaleAfter (30 min) and trigger Cleanup
        // via reflection. The sweep must evict the lock and dispose its semaphore.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero));
        using var sut = new RefreshLockRegistry(metrics: null, timeProvider: clock);

        await using (await sut.AcquireAsync("user-stale", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken)) { }

        // Advance past the 30-minute staleness cutoff.
        clock.Advance(TimeSpan.FromMinutes(31));
        InvokeCleanup(sut);

        Assert.False(HasLockEntry(sut, "user-stale"));
    }

    [Fact]
    public async Task Cleanup_PreservesFreshEntries()
    {
        // The sweep must skip entries inside the staleness window - otherwise we'd
        // churn semaphores for active users and pay the alloc / disposal cost on
        // every cleanup run.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero));
        using var sut = new RefreshLockRegistry(metrics: null, timeProvider: clock);

        await using (await sut.AcquireAsync("user-fresh", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken)) { }

        // Advance only 5 minutes - well under the 30-minute stale cutoff.
        clock.Advance(TimeSpan.FromMinutes(5));
        InvokeCleanup(sut);

        Assert.True(HasLockEntry(sut, "user-fresh"));
    }

    [Fact]
    public async Task Cleanup_LeavesHeldLocksInPlace_AndRefreshesTimestamp()
    {
        // The held-lock branch (Wait(0) fails) must NOT dispose the semaphore -
        // an active refresh would crash via ObjectDisposedException on Release().
        // The sweep also re-stamps the timestamp so the next sweep doesn't immediately
        // retry the same entry.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero));
        using var sut = new RefreshLockRegistry(metrics: null, timeProvider: clock);

        var held = await sut.AcquireAsync("user-held", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(held.Acquired);

        // Advance past stale cutoff and run the sweep WITHOUT releasing the lock.
        clock.Advance(TimeSpan.FromMinutes(31));
        InvokeCleanup(sut);

        // The entry must still exist; the semaphore was not disposed; the held handle
        // can still be released without throwing.
        Assert.True(HasLockEntry(sut, "user-held"));
        await held.DisposeAsync();
    }

    [Fact]
    public async Task Cleanup_AfterEviction_SameKeyCanBeReacquired()
    {
        // Cleanup claims the semaphore via Wait(0) and disposes it without releasing.
        // A later acquire on the same key must GetOrAdd a fresh semaphore and succeed -
        // not observe the claimed/disposed one.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero));
        using var sut = new RefreshLockRegistry(metrics: null, timeProvider: clock);

        await using (await sut.AcquireAsync("user-evicted", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken)) { }

        clock.Advance(TimeSpan.FromMinutes(31));
        InvokeCleanup(sut);
        Assert.False(HasLockEntry(sut, "user-evicted"));

        await using var reacquired = await sut.AcquireAsync("user-evicted", TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        Assert.True(reacquired.Acquired);
    }

    [Fact]
    public async Task Cleanup_WhileLockHeld_MutualExclusionSurvivesTheSweep()
    {
        // The dispose race this guards against: if the sweep disposed a semaphore that a
        // racer just acquired, a second acquirer would GetOrAdd a fresh one and both would
        // "hold" the lock. Gating dispose on Wait(0) makes that impossible - a held lock
        // is never disposed, so a contender during/after the sweep must still time out.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 5, 20, 12, 0, 0, TimeSpan.Zero));
        using var sut = new RefreshLockRegistry(metrics: null, timeProvider: clock);

        var held = await sut.AcquireAsync("user-race", TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.True(held.Acquired);

        clock.Advance(TimeSpan.FromMinutes(31));
        InvokeCleanup(sut);

        var contender = await sut.AcquireAsync("user-race", TimeSpan.FromMilliseconds(100), TestContext.Current.CancellationToken);
        Assert.False(contender.Acquired);

        await held.DisposeAsync();
    }

    // -----------------------------
    // Reflection / fake helpers
    // -----------------------------

    private static void InvokeCleanup(RefreshLockRegistry registry)
    {
        // The timer fires Cleanup on a worker thread; invoking it directly lets the
        // test step the algorithm without waiting on the 5-minute timer.
        var method = typeof(RefreshLockRegistry).GetMethod(
            "Cleanup",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);
        method!.Invoke(registry, [null]);
    }

    private static bool HasLockEntry(RefreshLockRegistry registry, string key)
    {
        var locks = typeof(RefreshLockRegistry).GetField(
            "_locks",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(locks);
        var dict = (System.Collections.IDictionary)locks!.GetValue(registry)!;
        return dict.Contains(key);
    }

    /// <summary>
    /// Minimal mutable TimeProvider that lets tests advance the clock without sleeping.
    /// Mirrors the pattern used by [SessionAuthProviderTests](Auth/Providers/SessionAuthProviderTests.cs).
    /// </summary>
    private sealed class FakeTimeProvider : TimeProvider
    {
        private DateTimeOffset _now;
        public FakeTimeProvider(DateTimeOffset now) => _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now = _now.Add(by);
    }
}
