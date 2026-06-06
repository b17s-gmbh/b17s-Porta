namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Coordinates concurrent access-token refreshes for the same principal so that
/// only one refresh fires at a time per <paramref name="lockKey"/>.
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

    public bool Acquired { get; } = acquired;

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

    public static RefreshLockHandle NotAcquired { get; } = new(false);
}
