namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Coordinates concurrent access-token refreshes for the same principal so that
/// only one refresh fires at a time per lock key (one key per user/session).
///
/// The default registration depends on what is wired before
/// <c>AddPortaAuthentication</c> runs:
/// <list type="bullet">
///   <item>If a real <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>
///   is registered (Redis/Valkey), the auto-pick installs <see cref="DistributedCacheRefreshLock"/>
///   so refreshes are serialized across replicas.</item>
///   <item>Otherwise the auto-pick installs <see cref="RefreshLockRegistry"/>, which is
///   process-local and the right choice for single-instance dev/test.</item>
///   <item>A consumer-provided <see cref="IRefreshLock"/> registration always wins.</item>
/// </list>
///
/// The startup check refuses to boot in non-Development if a distributed cache is
/// registered (multi-replica intent) but the in-process <see cref="RefreshLockRegistry"/>
/// was explicitly registered and not acknowledged via
/// <see cref="b17s.Porta.Extensions.RefreshLockExtensions.AcknowledgeInProcessRefreshLock"/>.
///
/// See docs/ha-deployment.md.
/// </summary>
public interface IRefreshLock
{
    /// <summary>
    /// Acquire the lock for <paramref name="lockKey"/>. Returns an <see cref="IAsyncDisposable"/>
    /// whose <see cref="IAsyncDisposable.DisposeAsync"/> releases the lock. If the lock cannot
    /// be acquired within <paramref name="timeout"/>, the returned handle's <see cref="RefreshLockHandle.Acquired"/>
    /// is false and the caller should fall back to a stale access token.
    ///
    /// Implementations must not let infrastructure faults (coordination store down, timed out)
    /// escape this method or the handle's <see cref="IAsyncDisposable.DisposeAsync"/>: report a
    /// not-acquired handle instead so callers degrade to the stale token. Only cancellation of
    /// <paramref name="cancellationToken"/> should propagate as an exception.
    /// </summary>
    Task<RefreshLockHandle> AcquireAsync(string lockKey, TimeSpan timeout, CancellationToken cancellationToken = default);
}

/// <summary>
/// Handle returned by <see cref="IRefreshLock.AcquireAsync"/>. Always disposable; check
/// <see cref="Acquired"/> before treating the lock as held.
/// </summary>
public sealed class RefreshLockHandle(bool acquired, Func<ValueTask>? release = null) : IAsyncDisposable
{
    private int _disposed;

    /// <summary>
    /// Whether the lock was successfully acquired. When <see langword="false"/> the caller did
    /// not win the lock (it timed out or another holder is active) and should fall back to serving
    /// a stale access token rather than performing a refresh. Disposing a not-acquired handle is a
    /// no-op.
    /// </summary>
    public bool Acquired { get; } = acquired;

    /// <summary>
    /// Releases the lock if it was acquired. Idempotent: only the first call runs the release
    /// callback; subsequent calls are no-ops. Does nothing when the handle was not acquired.
    /// </summary>
    /// <returns>A task that completes once the lock has been released.</returns>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        if (release is not null)
        {
            await release();
        }
    }

    /// <summary>
    /// A shared handle representing a failed acquisition (<see cref="Acquired"/> is
    /// <see langword="false"/>, with no release callback). Returned by implementations when the
    /// lock could not be obtained within the requested timeout.
    /// </summary>
    public static RefreshLockHandle NotAcquired { get; } = new(false);
}
