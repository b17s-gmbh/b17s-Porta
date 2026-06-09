using System.Text;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Best-effort cross-replica coordination for access-token refresh, backed by
/// <see cref="IDistributedCache"/>. <b>Not a true mutex</b> - tolerates a rare
/// double-refresh under contention. With strict-rotation IdPs (Auth0, Okta with
/// rotation, IdentityServer with <c>Sliding</c>+rotation) the losing replica's
/// refresh token is invalidated by the winner, producing an isolated re-login
/// for that one user. Worst case is bounded: re-authentication, not data loss
/// or token leakage.
///
/// <para>
/// <see cref="IDistributedCache"/> does not expose an atomic SET-NX, so
/// acquisition is a get-then-set-then-verify sequence with a per-acquire
/// fencing token. Under contention the loser usually observes the winner's
/// token on the verify step and reports the lock as not acquired - but a small
/// race window between the read and the write remains where both replicas can
/// proceed. Release is a best-effort compare-and-delete (read token, delete only
/// if it still matches) which narrows - but does not eliminate - the window in
/// which a delayed disposer evicts the next holder's lock: <see cref="IDistributedCache"/>
/// exposes no atomic check-and-delete, so the entry can expire and be re-acquired
/// by another replica between this read and the delete.
/// </para>
///
/// <para>
/// For deployments where the rare double-refresh is unacceptable, swap this
/// implementation by registering your own <see cref="IRefreshLock"/> (e.g. a
/// Redis-native <c>SET NX PX</c> adapter) before <c>AddPortaAuthentication</c>.
/// The HA startup check refuses to boot multi-replica deployments using the
/// in-process fallback unless explicitly acknowledged; see
/// <c>docs/ha-deployment.md</c>.
/// </para>
///
/// <para>
/// The TTL bounds how long a crashed acquirer can block other replicas; the
/// caller's <c>timeout</c> bounds how long this method waits for the lock.
/// Backoff between probe attempts is jittered to avoid thundering-herd retries.
/// </para>
///
/// <para>
/// A cache outage (Redis down, timeout) is reported as a not-acquired handle rather
/// than thrown: per the <see cref="IRefreshLock"/> contract the caller then serves the
/// stale access token, so losing the coordination store degrades to a possible
/// double-refresh instead of failing still-valid sessions.
/// </para>
/// </summary>
internal sealed class DistributedCacheRefreshLock(
    IDistributedCache cache,
    TimeProvider? timeProvider = null,
    ILogger<DistributedCacheRefreshLock>? logger = null) : IRefreshLock
{
    private const string KeyPrefix = "porta:refresh-lock:";
    private static readonly TimeSpan LockTtl = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MinBackoff = TimeSpan.FromMilliseconds(25);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromMilliseconds(150);

    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<RefreshLockHandle> AcquireAsync(string lockKey, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var cacheKey = KeyPrefix + lockKey;
        var token = Guid.NewGuid().ToString("N");
        var tokenBytes = Encoding.UTF8.GetBytes(token);
        var deadline = _timeProvider.GetUtcNow() + timeout;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var existing = await cache.GetAsync(cacheKey, cancellationToken);
                if (existing is null)
                {
                    await cache.SetAsync(cacheKey, tokenBytes, new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = LockTtl,
                    }, cancellationToken);

                    var verify = await cache.GetAsync(cacheKey, cancellationToken);
                    if (verify is not null && BytesEqual(verify, tokenBytes))
                    {
                        return new RefreshLockHandle(true, () => ReleaseAsync(cacheKey, tokenBytes));
                    }
                    // Lost the race; another replica's token is in the slot. Fall through to wait.
                }
            }
            catch (Exception ex) when (!ex.IsCanceledBy(cancellationToken))
            {
                // Cache outage: report not-acquired so the caller falls back to the stale
                // token, instead of escalating an infrastructure fault into an auth failure.
                logger?.RefreshLockCacheUnavailable(ex);
                return RefreshLockHandle.NotAcquired;
            }

            if (_timeProvider.GetUtcNow() >= deadline)
            {
                return RefreshLockHandle.NotAcquired;
            }

            var remaining = deadline - _timeProvider.GetUtcNow();
            var backoff = TimeSpan.FromMilliseconds(
                Random.Shared.Next((int)MinBackoff.TotalMilliseconds, (int)MaxBackoff.TotalMilliseconds));
            if (backoff > remaining)
            {
                backoff = remaining;
            }
            await Task.Delay(backoff, cancellationToken);
        }
    }

    private async ValueTask ReleaseAsync(string cacheKey, byte[] expectedToken)
    {
        try
        {
            var current = await cache.GetAsync(cacheKey);
            if (current is not null && BytesEqual(current, expectedToken))
            {
                await cache.RemoveAsync(cacheKey);
            }
        }
        catch (Exception ex)
        {
            // Best-effort: an unreleased lock self-evicts when its TTL expires, so a cache
            // outage during release must not surface through the handle's DisposeAsync.
            logger?.RefreshLockReleaseFailed(ex);
        }
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }
        for (var i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }
}

internal static partial class DistributedCacheRefreshLockLogging
{
    [LoggerMessage(EventId = 14405, Level = LogLevel.Warning,
        Message = "Refresh-lock cache unavailable; treating lock as not acquired so the stale access token is served")]
    public static partial void RefreshLockCacheUnavailable(this ILogger logger, Exception ex);

    [LoggerMessage(EventId = 14406, Level = LogLevel.Warning,
        Message = "Refresh-lock release failed; the lock will self-evict when its TTL expires")]
    public static partial void RefreshLockReleaseFailed(this ILogger logger, Exception ex);
}
