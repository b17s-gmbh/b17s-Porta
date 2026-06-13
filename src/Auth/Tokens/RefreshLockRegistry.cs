using System.Collections.Concurrent;

using b17s.Porta.Telemetry;

using Microsoft.Extensions.Logging;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Process-local <see cref="IRefreshLock"/> implementation. Singleton-scoped so the
/// cleanup timer's lifetime is tied to the host (disposed on shutdown) rather than
/// living forever on a static field.
///
/// In multi-instance deployments this lock only coordinates within a single replica.
/// See <see cref="IRefreshLock"/> for the trade-off and remediation.
/// </summary>
internal sealed class RefreshLockRegistry : IRefreshLock, IDisposable
{
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(30);

    private readonly Timer _cleanupTimer;
    private readonly CancellationTokenSource _cts = new();
    private readonly PortaMetrics? _metrics;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger? _logger;
    private int _disposed;

    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastAccess = new();

    public RefreshLockRegistry(PortaMetrics? metrics = null, TimeProvider? timeProvider = null, ILogger<RefreshLockRegistry>? logger = null)
    {
        _metrics = metrics;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger;
        _cleanupTimer = new Timer(Cleanup, null, CleanupInterval, CleanupInterval);
    }

    public async Task<RefreshLockHandle> AcquireAsync(string lockKey, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        // Stamp the timestamp BEFORE the GetOrAdd to close the cleanup race:
        // an interleaved Cleanup sweep that observes a stale timestamp here
        // will see the refreshed value before deciding to evict.
        _lastAccess[lockKey] = _timeProvider.GetUtcNow();
        var semaphore = _locks.GetOrAdd(lockKey, _ => new SemaphoreSlim(1, 1));

        try
        {
            if (!await semaphore.WaitAsync(timeout, cancellationToken))
            {
                return RefreshLockHandle.NotAcquired;
            }
        }
        catch (ObjectDisposedException)
        {
            // Cleanup raced ahead between GetOrAdd and WaitAsync. Treat as
            // "lock unavailable" - the caller's stale-token fallback handles
            // this exactly like a timeout.
            if (_logger is not null) _logger.LockAcquisitionRacedDisposal();
            return RefreshLockHandle.NotAcquired;
        }

        return new RefreshLockHandle(true, () =>
        {
            // Cleanup may have disposed the semaphore between acquisition and
            // release (shutdown/eviction race). Releasing a disposed semaphore is
            // a no-op from the caller's perspective - the lock is already gone.
            try { semaphore.Release(); }
            catch (ObjectDisposedException) { if (_logger is not null) _logger.LockReleaseRacedDisposal(); }
            return ValueTask.CompletedTask;
        });
    }

    private void Cleanup(object? _)
    {
        if (_cts.IsCancellationRequested)
        {
            return;
        }

        var cutoff = _timeProvider.GetUtcNow() - StaleAfter;
        var stale = _lastAccess.Where(x => x.Value < cutoff).Select(x => x.Key).ToList();
        var removed = 0;

        foreach (var key in stale)
        {
            // Race: between the staleness check and the dispose below, an
            // AcquireAsync caller may have refreshed `_lastAccess[key]` and
            // already entered WaitAsync on the semaphore. Re-check the
            // timestamp under the entry's own slot, then claim the semaphore
            // with Wait(0): a successful claim proves nobody holds it AND
            // prevents anyone from acquiring it before we dispose - a bare
            // CurrentCount check would leave a window where a racer acquires
            // between the check and the dispose, breaking mutual exclusion.
            if (!_lastAccess.TryGetValue(key, out var lastSeen) || lastSeen >= cutoff)
            {
                continue;
            }
            if (!_locks.TryGetValue(key, out var semaphore))
            {
                _lastAccess.TryRemove(key, out DateTimeOffset _);
                continue;
            }
            try
            {
                if (!semaphore.Wait(0))
                {
                    // Someone is holding it - don't dispose out from under them.
                    // Refresh the timestamp to defer the next cleanup attempt so
                    // we don't spin on a long-held lock.
                    _lastAccess[key] = _timeProvider.GetUtcNow();
                    continue;
                }
            }
            catch (ObjectDisposedException)
            {
                // Shutdown Dispose() (or an overlapping sweep) already disposed
                // this semaphore; nothing left to clean up for this key.
                continue;
            }

            // We hold the semaphore: remove first, then dispose (never released -
            // the instance is gone). A racing AcquireAsync after this line will
            // `GetOrAdd` a fresh semaphore - it will not see the disposed one.
            // A consumer that already passed `GetOrAdd` but not yet `WaitAsync`
            // either times out (we hold the count) or sees ObjectDisposedException;
            // both map to the documented `NotAcquired` outcome.
            if (_locks.TryRemove(key, out var removedSemaphore))
            {
                _lastAccess.TryRemove(key, out DateTimeOffset _);
                removedSemaphore.Dispose();
                removed++;
            }
        }

        _metrics?.RecordLockCleanup(removed);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _cts.Cancel();
        _cleanupTimer.Dispose();

        foreach (var semaphore in _locks.Values)
        {
            semaphore.Dispose();
        }

        _locks.Clear();
        _lastAccess.Clear();
        _cts.Dispose();
    }
}

/// <summary>
/// High-performance logging for <see cref="RefreshLockRegistry"/> using compile-time source generators.
/// </summary>
internal static partial class RefreshLockRegistryLogging
{
    [LoggerMessage(EventId = 14410, Level = LogLevel.Debug,
        Message = "Refresh lock acquisition raced semaphore disposal during cleanup; treated as not-acquired (caller falls back to stale-token path)")]
    public static partial void LockAcquisitionRacedDisposal(this ILogger logger);

    [LoggerMessage(EventId = 14411, Level = LogLevel.Debug,
        Message = "Refresh lock release raced semaphore disposal during cleanup; release is a no-op")]
    public static partial void LockReleaseRacedDisposal(this ILogger logger);
}
