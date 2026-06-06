using Microsoft.Extensions.DependencyInjection;

namespace b17s.Porta.Extensions;

/// <summary>
/// Extension methods for opting out of the secure-by-default <see cref="b17s.Porta.Auth.Tokens.IRefreshLock"/>
/// behaviour. By default <see cref="AuthenticationServiceExtensions.AddPortaAuthentication"/>
/// auto-registers the <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>-backed
/// lock when a real distributed cache is present, and refuses to start in non-Development
/// when a multi-replica deployment would silently use the in-process fallback.
///
/// Single-instance dev/test deployments are unaffected - without a distributed cache
/// the in-process fallback is the correct choice and no acknowledgement is required.
///
/// See docs/ha-deployment.md.
/// </summary>
public static class RefreshLockExtensions
{
    /// <summary>
    /// Marker registration that records the consuming app has explicitly chosen the
    /// in-process refresh lock despite running with a distributed cache configured.
    /// Suppresses the secure-by-default startup throw on single-box production
    /// deployments.
    /// </summary>
    internal sealed record PortaInProcessRefreshLockAcknowledgement(string Reason);

    /// <summary>
    /// Acknowledges that the in-process <see cref="b17s.Porta.Auth.Tokens.IRefreshLock"/>
    /// is intentional even though a distributed cache is registered. By default
    /// <see cref="AuthenticationServiceExtensions.AddPortaAuthentication"/> refuses to
    /// start in non-Development environments under that combination, on the assumption
    /// that a distributed cache implies a multi-replica deployment where cross-replica
    /// refresh races against a strict-rotation IdP would produce spurious sign-outs.
    ///
    /// Call this only on a single-box deployment (one replica) that happens to use
    /// a remote cache for other reasons. Do not use it to silence the check on a
    /// real multi-replica deployment - register a distributed
    /// <see cref="b17s.Porta.Auth.Tokens.IRefreshLock"/> implementation instead.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="reason">A human-readable justification recorded with the acknowledgement
    /// (e.g. <c>"single VM, shared Redis used only for cache"</c>). Required so the choice
    /// is reviewable in the call site rather than silent.</param>
    public static IServiceCollection AcknowledgeInProcessRefreshLock(
        this IServiceCollection services,
        string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        services.AddSingleton(new PortaInProcessRefreshLockAcknowledgement(reason));
        return services;
    }

    internal static bool IsInProcessRefreshLockAcknowledged(IServiceCollection services)
    {
        foreach (var descriptor in services)
        {
            if (descriptor.ServiceType == typeof(PortaInProcessRefreshLockAcknowledgement))
            {
                return true;
            }
        }
        return false;
    }
}
