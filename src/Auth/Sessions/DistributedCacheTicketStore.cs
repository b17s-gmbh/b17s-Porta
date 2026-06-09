using System.Security.Cryptography;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Auth.Sessions;

/// <summary>
/// Server-side <see cref="ITicketStore"/> backed by <see cref="IDistributedCache"/>.
///
/// Used as the SessionStore for the cookie auth handler so that the auth cookie
/// only carries an opaque ticket id, not the access/refresh/id tokens themselves.
/// Tickets are protected at rest via <see cref="IDataProtector"/>.
/// </summary>
public sealed class DistributedCacheTicketStore(
    IDistributedCache cache,
    IDataProtectionProvider dataProtectionProvider,
    IOptions<TicketStoreOptions> options,
    ILogger<DistributedCacheTicketStore> logger) : ITicketStore
{
    /// <summary>
    /// AuthenticationProperties.Items key under which the BFF-assigned sessionId is
    /// stashed by <c>OnTokenValidated</c>. When present, we use it as the ticket key
    /// so that <see cref="ISessionManagementService"/> metadata and the ticket
    /// itself share an address space, and so that admin/back-channel logout can
    /// remove both with the same id.
    /// </summary>
    private const string SessionIdPropertyKey = ".bff.session_id";

    private readonly TicketStoreOptions _options = options.Value;
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(options.Value.DataProtectorPurpose);

    /// <inheritdoc/>
    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);

        var key = GetOrCreateSessionId(ticket);
        await RenewAsync(key, ticket);
        return key;
    }

    private static string GetOrCreateSessionId(AuthenticationTicket ticket) =>
        ticket.Properties.Items.TryGetValue(SessionIdPropertyKey, out var id) && !string.IsNullOrEmpty(id)
            ? id
            : Guid.NewGuid().ToString("N");

    /// <inheritdoc/>
    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(ticket);

        var serialized = TicketSerializer.Default.Serialize(ticket);
        var protectedBytes = _protector.Protect(serialized);

        var cacheOptions = new DistributedCacheEntryOptions();
        var expiresUtc = ticket.Properties.ExpiresUtc;
        if (expiresUtc.HasValue)
        {
            cacheOptions.AbsoluteExpiration = expiresUtc.Value;
        }
        else
        {
            cacheOptions.SlidingExpiration = _options.DefaultSlidingExpiration;
        }

        await cache.SetAsync(BuildKey(key), protectedBytes, cacheOptions);
        logger.TicketRenewed(LogRedaction.RedactSessionId(key));
    }

    /// <inheritdoc/>
    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return null;
        }

        var protectedBytes = await cache.GetAsync(BuildKey(key));
        if (protectedBytes is null || protectedBytes.Length == 0)
        {
            return null;
        }

        byte[] serialized;
        try
        {
            serialized = _protector.Unprotect(protectedBytes);
        }
        catch (CryptographicException ex)
        {
            logger.TicketDecryptFailed(LogRedaction.RedactSessionId(key), ex);
            return null;
        }

        try
        {
            return TicketSerializer.Default.Deserialize(serialized);
        }
        catch (Exception ex)
        {
            logger.TicketDeserializeFailed(LogRedaction.RedactSessionId(key), ex);
            return null;
        }
    }

    /// <inheritdoc/>
    public async Task RemoveAsync(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return;
        }

        await cache.RemoveAsync(BuildKey(key));
        logger.TicketRemoved(LogRedaction.RedactSessionId(key));
    }

    private string BuildKey(string id) => _options.CacheKeyPrefix + id;
}

internal static partial class DistributedCacheTicketStoreLogging
{
    [LoggerMessage(EventId = 14300, Level = LogLevel.Debug,
        Message = "Auth ticket renewed: {SessionIdHash}")]
    public static partial void TicketRenewed(this ILogger logger, string sessionIdHash);

    [LoggerMessage(EventId = 14301, Level = LogLevel.Debug,
        Message = "Auth ticket removed: {SessionIdHash}")]
    public static partial void TicketRemoved(this ILogger logger, string sessionIdHash);

    [LoggerMessage(EventId = 14302, Level = LogLevel.Warning,
        Message = "Failed to decrypt auth ticket {SessionIdHash} (data protection key rotation?)")]
    public static partial void TicketDecryptFailed(this ILogger logger, string sessionIdHash, Exception ex);

    [LoggerMessage(EventId = 14303, Level = LogLevel.Error,
        Message = "Failed to deserialize auth ticket {SessionIdHash} after successful decryption")]
    public static partial void TicketDeserializeFailed(this ILogger logger, string sessionIdHash, Exception ex);
}
