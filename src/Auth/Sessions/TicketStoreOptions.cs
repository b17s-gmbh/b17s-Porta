namespace b17s.Porta.Auth.Sessions;

/// <summary>
/// Configuration for <see cref="DistributedCacheTicketStore"/>.
/// </summary>
public sealed class TicketStoreOptions
{
    /// <summary>
    /// Prefix for ticket entries in the distributed cache.
    /// Default: "porta:auth_ticket:".
    /// </summary>
    public string CacheKeyPrefix { get; set; } = "porta:auth_ticket:";

    /// <summary>
    /// IDataProtector purpose used to protect serialized tickets at rest.
    /// Default: "Porta.AuthTickets.v1".
    /// </summary>
    public string DataProtectorPurpose { get; set; } = "Porta.AuthTickets.v1";

    /// <summary>
    /// Sliding expiration applied to ticket entries when no explicit lifetime
    /// is set on the ticket itself. Default: 60 minutes.
    /// </summary>
    public TimeSpan DefaultSlidingExpiration { get; set; } = TimeSpan.FromMinutes(60);
}
