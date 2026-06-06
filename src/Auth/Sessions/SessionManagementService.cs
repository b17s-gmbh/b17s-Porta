using System.Security.Cryptography;
using System.Text.Json;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Auth.Sessions;

/// <summary>
/// Implements session management by working with ASP.NET Core's distributed session store.
/// Maintains an email-to-sessionIds index for admin lookups.
///
/// Architecture:
/// - Tokens are stored on the cookie auth ticket (via the OIDC handler's SaveTokens),
///   persisted server-side by <see cref="DistributedCacheTicketStore"/>.
/// - This service maintains a lightweight email→sessionIds index for admin queries
///   plus an optional encrypted refresh token used for IdP-side revocation.
/// </summary>
public sealed class SessionManagementService(
    IDistributedCache cache,
    IOptions<SessionAuthenticationConfiguration> configOptions,
    ILogger<SessionManagementService> logger,
    ITicketStore? ticketStore = null,
    ITokenRevocationService? tokenRevocationService = null,
    IDataProtectionProvider? dataProtectionProvider = null,
    Tokens.IRefreshLock? indexLock = null,
    TimeProvider? timeProvider = null) : ISessionManagementService
{
    private const string RevocationProtectorPurpose = "Porta.SessionTokenRevocation.v1";

    private readonly SessionAuthenticationConfiguration config = configOptions.Value;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    private readonly IDataProtector? _revocationProtector =
        dataProtectionProvider?.CreateProtector(RevocationProtectorPurpose);

    // Our custom index for email lookups
    private const string EmailIndexPrefix = "porta:email_sessions:";

    // Subject (OIDC `sub` claim) index. Used by back-channel logout, which receives
    // the IdP-scoped subject identifier (typically a UUID) rather than an email.
    private const string SubjectIndexPrefix = "porta:sub_sessions:";

    // Session metadata prefix (we store minimal info alongside ASP.NET Core session)
    private const string SessionMetadataPrefix = "porta:session_meta:";

    // Lock-key prefixes used to serialize read-modify-write of the email/subject indexes.
    // Without this, two concurrent logins for the same subject can both read [], both
    // write [their own sessionId], and admin "logout all sessions for X" silently misses
    // the loser's session - breaking the documented revocation guarantee.
    private const string EmailIndexLockPrefix = "porta:email_sessions_lock:";
    private const string SubjectIndexLockPrefix = "porta:sub_sessions_lock:";
    private static readonly TimeSpan IndexLockTimeout = TimeSpan.FromSeconds(5);

    private DistributedCacheEntryOptions IndexEntryOptions => new()
    {
        SlidingExpiration = TimeSpan.FromMinutes(config.SessionTimeoutInMin)
    };

    /// <summary>
    /// Registers a session keyed by the OIDC <c>sub</c> claim. Email is an optional
    /// secondary index - we only add it when the caller passes a value, which by
    /// convention means the IdP asserted <c>email_verified=true</c>.
    /// </summary>
    public async Task RegisterSessionAsync(string sessionId, string userId, string? email = null, string? ipAddress = null, string? userAgent = null, string? encryptedRefreshToken = null)
    {
        if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(userId))
            return;

        var normalizedEmail = string.IsNullOrEmpty(email) ? null : email.ToLowerInvariant();

        var metadata = new SessionInfo
        {
            SessionId = sessionId,
            Email = normalizedEmail,
            UserId = userId,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            CreatedAt = _timeProvider.GetUtcNow(),
            LastActivity = _timeProvider.GetUtcNow(),
            EncryptedRefreshToken = encryptedRefreshToken,
        };

        var metadataKey = $"{SessionMetadataPrefix}{sessionId}";
        await cache.SetStringAsync(metadataKey, JsonSerializer.Serialize(metadata), new DistributedCacheEntryOptions
        {
            SlidingExpiration = TimeSpan.FromMinutes(config.SessionTimeoutInMin)
        });

        // Subject index is the load-bearing path for back-channel logout and admin
        // revocation; surfacing a failure here is preferable to leaving a session
        // logged-in-but-unrevocable (a security regression vs. reference-token mode).
        try
        {
            await AddToSubjectIndexAsync(userId, sessionId);
        }
        catch (Exception ex)
        {
            logger.RegisterSessionError(LogRedaction.RedactSessionId(sessionId), ex);
            // Roll back the metadata write so the session is not partially registered.
            try { await cache.RemoveAsync(metadataKey); }
            catch (Exception cleanupEx)
            {
                // Best-effort rollback; the original RegisterSession failure is rethrown
                // below. Type only - the cache key embeds the (Secret-classified) session id.
                logger.SessionMetadataRollbackCleanupFailed(cleanupEx.GetType().Name);
            }
            throw;
        }

        if (normalizedEmail is not null)
        {
            try
            {
                await AddToEmailIndexAsync(normalizedEmail, sessionId);
            }
            catch (Exception ex)
            {
                // Email index is a secondary lookup convenience; failing here should not
                // tear down a valid, fully-revocable session. Log loudly and continue.
                logger.RegisterSessionEmailIndexFailed(LogRedaction.RedactSessionId(sessionId), ex);
            }
        }

        logger.SessionRegistered(LogRedaction.RedactSessionId(sessionId), userId, LogRedaction.FingerprintSubject(userId));
    }

    public async Task UpdateRefreshTokenAsync(string sessionId, string? encryptedRefreshToken)
    {
        if (string.IsNullOrEmpty(sessionId))
            return;

        try
        {
            var metadataKey = $"{SessionMetadataPrefix}{sessionId}";
            var json = await cache.GetStringAsync(metadataKey);
            if (string.IsNullOrEmpty(json))
            {
                return;
            }

            var metadata = JsonSerializer.Deserialize<SessionInfo>(json);
            if (metadata is null)
            {
                return;
            }

            metadata.EncryptedRefreshToken = encryptedRefreshToken;
            metadata.LastActivity = _timeProvider.GetUtcNow();

            await cache.SetStringAsync(metadataKey, JsonSerializer.Serialize(metadata), new DistributedCacheEntryOptions
            {
                SlidingExpiration = TimeSpan.FromMinutes(config.SessionTimeoutInMin)
            });
        }
        catch (Exception ex)
        {
            logger.UpdateRefreshTokenError(LogRedaction.RedactSessionId(sessionId), ex);
        }
    }

    public async Task<IReadOnlyList<SessionInfo>> GetSessionsByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(email))
        {
            logger.EmailInputInvalid();
            return [];
        }

        try
        {
            var normalizedEmail = email.ToLowerInvariant();
            var sessionIds = await GetEmailIndexAsync(normalizedEmail, cancellationToken);

            if (sessionIds.Count == 0)
                return [];

            var sessions = new List<SessionInfo>();
            var expiredSessionIds = new List<string>();

            foreach (var sessionId in sessionIds)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var metadata = await GetSessionMetadataAsync(sessionId, cancellationToken);
                if (metadata != null)
                {
                    // Verify the ASP.NET Core session still exists
                    if (await SessionExistsAsync(sessionId))
                    {
                        sessions.Add(metadata);
                    }
                    else
                    {
                        expiredSessionIds.Add(sessionId);
                    }
                }
                else
                {
                    expiredSessionIds.Add(sessionId);
                }
            }

            // Clean up expired sessions from index
            if (expiredSessionIds.Count > 0)
            {
                await RemoveFromEmailIndexAsync(normalizedEmail, expiredSessionIds, cancellationToken);
            }

            return sessions;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.GetSessionsByEmailError(email, LogRedaction.FingerprintEmail(email), ex);
            return [];
        }
    }

    public async Task<bool> TerminateSessionAsync(string sessionId, bool revokeTokens = true, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(sessionId))
        {
            logger.SessionIdInputInvalid();
            return false;
        }

        try
        {
            var metadata = await GetSessionMetadataAsync(sessionId, cancellationToken);

            if (revokeTokens && metadata != null)
            {
                await TryRevokeSessionTokensAsync(sessionId, cancellationToken);
            }

            await RemoveAuthTicketAsync(sessionId);
            await RemoveSessionMetadataAsync(sessionId, cancellationToken);
            await RemoveFromIndexesAsync(sessionId, metadata, cancellationToken);

            logger.SessionTerminated(metadata?.Email ?? LogRedaction.RedactSessionId(sessionId), LogRedaction.FingerprintEmail(metadata?.Email), LogRedaction.RedactSessionId(sessionId), revokeTokens);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.TerminateSessionError(LogRedaction.RedactSessionId(sessionId), ex);
            return false;
        }
    }

    public async Task<int> TerminateSessionsByEmailAsync(string email, bool revokeTokens = true, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(email))
        {
            logger.EmailInputInvalid();
            return 0;
        }

        try
        {
            var sessions = await GetSessionsByEmailAsync(email, cancellationToken);
            if (sessions.Count == 0)
                return 0;

            var terminatedCount = 0;
            foreach (var session in sessions)
            {
                if (await TerminateSessionAsync(session.SessionId, revokeTokens, cancellationToken))
                {
                    terminatedCount++;
                }
            }

            logger.SessionsTerminatedForEmail(terminatedCount, email, LogRedaction.FingerprintEmail(email));
            return terminatedCount;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.TerminateSessionsByEmailError(email, LogRedaction.FingerprintEmail(email), ex);
            return 0;
        }
    }

    public async Task<int> TerminateSessionsBySubjectAsync(string subject, bool revokeTokens = true, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(subject))
        {
            logger.SubjectInputInvalid();
            return 0;
        }

        try
        {
            var sessionIds = await GetSubjectIndexAsync(subject, cancellationToken);
            if (sessionIds.Count == 0)
            {
                return 0;
            }

            var terminatedCount = 0;
            foreach (var sessionId in sessionIds.ToArray())
            {
                if (await TerminateSessionAsync(sessionId, revokeTokens, cancellationToken))
                {
                    terminatedCount++;
                }
            }

            logger.SessionsTerminatedForSubject(terminatedCount, subject, LogRedaction.FingerprintSubject(subject));
            return terminatedCount;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.TerminateSessionsBySubjectError(subject, LogRedaction.FingerprintSubject(subject), ex);
            return 0;
        }
    }

    /// <summary>
    /// Updates the last activity time for a session.
    /// Call this periodically or on significant user activity.
    /// </summary>
    public async Task TouchSessionAsync(string sessionId)
    {
        try
        {
            var metadataKey = $"{SessionMetadataPrefix}{sessionId}";
            var metadataJson = await cache.GetStringAsync(metadataKey);

            if (string.IsNullOrEmpty(metadataJson))
                return;

            var metadata = JsonSerializer.Deserialize<SessionInfo>(metadataJson);
            if (metadata == null)
                return;

            metadata.LastActivity = _timeProvider.GetUtcNow();

            await cache.SetStringAsync(metadataKey, JsonSerializer.Serialize(metadata), new DistributedCacheEntryOptions
            {
                SlidingExpiration = TimeSpan.FromMinutes(config.SessionTimeoutInMin)
            });
        }
        catch (Exception ex)
        {
            logger.TouchSessionFailed(LogRedaction.RedactSessionId(sessionId), ex);
        }
    }

    private async Task RemoveAuthTicketAsync(string sessionId)
    {
        if (ticketStore is not null)
        {
            await ticketStore.RemoveAsync(sessionId);
        }
    }

    private Task RemoveSessionMetadataAsync(string sessionId, CancellationToken cancellationToken = default) =>
        cache.RemoveAsync($"{SessionMetadataPrefix}{sessionId}", cancellationToken);

    private async Task RemoveFromIndexesAsync(string sessionId, SessionInfo? metadata, CancellationToken cancellationToken = default)
    {
        if (metadata?.Email is not null)
        {
            await RemoveFromEmailIndexAsync(metadata.Email, [sessionId], cancellationToken);
        }

        if (!string.IsNullOrEmpty(metadata?.UserId))
        {
            await RemoveFromSubjectIndexAsync(metadata.UserId, [sessionId], cancellationToken);
        }
    }

    private async Task<SessionInfo?> GetSessionMetadataAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        try
        {
            var metadataKey = $"{SessionMetadataPrefix}{sessionId}";
            var metadataJson = await cache.GetStringAsync(metadataKey, cancellationToken);

            if (string.IsNullOrEmpty(metadataJson))
                return null;

            return JsonSerializer.Deserialize<SessionInfo>(metadataJson);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.GetSessionMetadataFailed(LogRedaction.RedactSessionId(sessionId), ex);
            return null;
        }
    }

    private async Task<bool> SessionExistsAsync(string sessionId)
    {
        // No ticket store → treat metadata existence as proof of liveness.
        // Returning false here would make GetSessionsByEmailAsync purge live sessions
        // in deployments without server-side ticket storage.
        if (ticketStore is null)
        {
            return true;
        }

        try
        {
            var ticket = await ticketStore.RetrieveAsync(sessionId);
            return ticket is not null;
        }
        catch (Exception ex)
        {
            logger.SessionExistsCheckFailed(LogRedaction.RedactSessionId(sessionId), ex);
            return false;
        }
    }

    private async Task<List<string>> GetEmailIndexAsync(string normalizedEmail, CancellationToken cancellationToken = default)
    {
        try
        {
            var indexKey = $"{EmailIndexPrefix}{normalizedEmail}";
            var indexJson = await cache.GetStringAsync(indexKey, cancellationToken);

            if (string.IsNullOrEmpty(indexJson))
                return [];

            // Touch to refresh the sliding TTL so an actively-queried index doesn't expire.
            await cache.RefreshAsync(indexKey, cancellationToken);

            return JsonSerializer.Deserialize<List<string>>(indexJson) ?? [];
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.GetEmailIndexFailed(normalizedEmail, LogRedaction.FingerprintEmail(normalizedEmail), ex);
            return [];
        }
    }

    private async Task AddToEmailIndexAsync(string normalizedEmail, string sessionId)
    {
        try
        {
            var indexKey = $"{EmailIndexPrefix}{normalizedEmail}";
            await using var handle = await AcquireIndexLockAsync(EmailIndexLockPrefix + normalizedEmail);
            if (!handle.Acquired)
            {
                // Best-effort fallback: skip the atomic update rather than risk a lost-update
                // race. Caller already logged a register-session failure-context elsewhere.
                logger.IndexLockTimedOut(indexKey);
                return;
            }

            var sessionIds = await GetEmailIndexAsync(normalizedEmail);

            if (!sessionIds.Contains(sessionId))
            {
                sessionIds.Add(sessionId);
                await cache.SetStringAsync(indexKey, JsonSerializer.Serialize(sessionIds), IndexEntryOptions);
            }
        }
        catch (Exception ex)
        {
            logger.AddToEmailIndexError(normalizedEmail, LogRedaction.FingerprintEmail(normalizedEmail), ex);
            throw;
        }
    }

    private async Task RemoveFromEmailIndexAsync(string normalizedEmail, List<string> sessionIdsToRemove, CancellationToken cancellationToken = default)
    {
        try
        {
            var indexKey = $"{EmailIndexPrefix}{normalizedEmail}";
            await using var handle = await AcquireIndexLockAsync(EmailIndexLockPrefix + normalizedEmail);
            if (!handle.Acquired)
            {
                logger.IndexLockTimedOut(indexKey);
                return;
            }

            var sessionIds = await GetEmailIndexAsync(normalizedEmail, cancellationToken);

            foreach (var sessionId in sessionIdsToRemove)
            {
                sessionIds.Remove(sessionId);
            }

            if (sessionIds.Count > 0)
            {
                await cache.SetStringAsync(indexKey, JsonSerializer.Serialize(sessionIds), IndexEntryOptions, cancellationToken);
            }
            else
            {
                await cache.RemoveAsync(indexKey, cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.RemoveFromEmailIndexError(normalizedEmail, LogRedaction.FingerprintEmail(normalizedEmail), ex);
        }
    }

    private async Task<List<string>> GetSubjectIndexAsync(string subject, CancellationToken cancellationToken = default)
    {
        try
        {
            var indexKey = $"{SubjectIndexPrefix}{subject}";
            var indexJson = await cache.GetStringAsync(indexKey, cancellationToken);

            if (string.IsNullOrEmpty(indexJson))
                return [];

            // Touch to refresh the sliding TTL so an actively-queried index doesn't expire.
            await cache.RefreshAsync(indexKey, cancellationToken);

            return JsonSerializer.Deserialize<List<string>>(indexJson) ?? [];
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.GetSubjectIndexFailed(subject, LogRedaction.FingerprintSubject(subject), ex);
            return [];
        }
    }

    private async Task AddToSubjectIndexAsync(string subject, string sessionId)
    {
        try
        {
            var indexKey = $"{SubjectIndexPrefix}{subject}";
            await using var handle = await AcquireIndexLockAsync(SubjectIndexLockPrefix + subject);
            if (!handle.Acquired)
            {
                logger.IndexLockTimedOut(indexKey);
                throw new InvalidOperationException(
                    $"Failed to acquire subject index lock for {subject} - session would be unrevokable.");
            }

            var sessionIds = await GetSubjectIndexAsync(subject);

            if (!sessionIds.Contains(sessionId))
            {
                sessionIds.Add(sessionId);
                await cache.SetStringAsync(indexKey, JsonSerializer.Serialize(sessionIds), IndexEntryOptions);
            }
        }
        catch (Exception ex)
        {
            logger.AddToSubjectIndexError(subject, LogRedaction.FingerprintSubject(subject), ex);
            throw;
        }
    }

    private async Task RemoveFromSubjectIndexAsync(string subject, List<string> sessionIdsToRemove, CancellationToken cancellationToken = default)
    {
        try
        {
            var indexKey = $"{SubjectIndexPrefix}{subject}";
            await using var handle = await AcquireIndexLockAsync(SubjectIndexLockPrefix + subject);
            if (!handle.Acquired)
            {
                logger.IndexLockTimedOut(indexKey);
                return;
            }

            var sessionIds = await GetSubjectIndexAsync(subject, cancellationToken);

            foreach (var sessionId in sessionIdsToRemove)
            {
                sessionIds.Remove(sessionId);
            }

            if (sessionIds.Count > 0)
            {
                await cache.SetStringAsync(indexKey, JsonSerializer.Serialize(sessionIds), IndexEntryOptions, cancellationToken);
            }
            else
            {
                await cache.RemoveAsync(indexKey, cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.RemoveFromSubjectIndexError(subject, LogRedaction.FingerprintSubject(subject), ex);
        }
    }

    /// <summary>
    /// Acquires a serializing lock for index read-modify-write. When no
    /// <see cref="Tokens.IRefreshLock"/> is registered the lock is a no-op handle -
    /// callers tolerate that for single-replica deployments where there is no
    /// cross-replica race. Multi-replica deployments register the distributed
    /// implementation via <c>AddPortaAuthentication</c>.
    /// </summary>
    private Task<Tokens.RefreshLockHandle> AcquireIndexLockAsync(string lockKey)
    {
        if (indexLock is null)
        {
            // No distributed lock available - degrade to "always acquired" so single-replica
            // dev/test still works. Multi-replica HA setups must register IRefreshLock.
            return Task.FromResult(new Tokens.RefreshLockHandle(true));
        }
        return indexLock.AcquireAsync(lockKey, IndexLockTimeout);
    }

    public string? ProtectRefreshToken(string? refreshToken)
    {
        if (string.IsNullOrEmpty(refreshToken) || _revocationProtector is null)
        {
            return null;
        }
        return _revocationProtector.Protect(refreshToken);
    }

    private async Task TryRevokeSessionTokensAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        if (tokenRevocationService is null)
        {
            logger.TokenRevocationServiceNotConfigured(LogRedaction.RedactSessionId(sessionId));
            return;
        }

        if (_revocationProtector is null)
        {
            logger.RevocationProtectorNotConfigured(LogRedaction.RedactSessionId(sessionId));
            return;
        }

        try
        {
            var metadata = await GetSessionMetadataAsync(sessionId, cancellationToken);
            if (metadata?.EncryptedRefreshToken is null)
            {
                logger.NoRefreshTokenStored(LogRedaction.RedactSessionId(sessionId));
                return;
            }

            string refreshToken;
            try
            {
                refreshToken = _revocationProtector.Unprotect(metadata.EncryptedRefreshToken);
            }
            catch (CryptographicException ex)
            {
                logger.RefreshTokenDecryptFailed(LogRedaction.RedactSessionId(sessionId), ex);
                return;
            }

            var revoked = await tokenRevocationService.RevokeTokenAsync(refreshToken, "refresh_token", cancellationToken);
            if (!revoked)
            {
                logger.RefreshTokenRevocationReturnedFalse(LogRedaction.RedactSessionId(sessionId));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.TokenRevocationFailed(LogRedaction.RedactSessionId(sessionId), ex);
        }
    }
}

/// <summary>
/// High-performance logging for SessionManagementService.
/// </summary>
internal static partial class SessionManagementServiceLogging
{
    [LoggerMessage(EventId = 13800, Level = LogLevel.Warning,
        Message = "Email input is null or empty")]
    public static partial void EmailInputInvalid(this ILogger logger);

    [LoggerMessage(EventId = 13801, Level = LogLevel.Warning,
        Message = "SessionId input is null or empty")]
    public static partial void SessionIdInputInvalid(this ILogger logger);

    [LoggerMessage(EventId = 13802, Level = LogLevel.Information,
        Message = "Session terminated for {UserIdentifier} ({UserHash}), sessionId: {SessionIdHash}, tokensRevoked: {TokensRevoked}")]
    public static partial void SessionTerminated(this ILogger logger, string userIdentifier, string userHash, string sessionIdHash, bool tokensRevoked);

    [LoggerMessage(EventId = 13803, Level = LogLevel.Information,
        Message = "Terminated {Count} sessions for email: {Email} ({EmailHash})")]
    public static partial void SessionsTerminatedForEmail(this ILogger logger, int count, string email, string emailHash);

    [LoggerMessage(EventId = 13804, Level = LogLevel.Error,
        Message = "Failed to register session {SessionIdHash}")]
    public static partial void RegisterSessionError(this ILogger logger, string sessionIdHash, Exception ex);

    [LoggerMessage(EventId = 13805, Level = LogLevel.Warning,
        Message = "Token revocation failed for session: {SessionIdHash}")]
    public static partial void TokenRevocationFailed(this ILogger logger, string sessionIdHash, Exception ex);

    [LoggerMessage(EventId = 13806, Level = LogLevel.Debug,
        Message = "Session registered: {SessionIdHash} for subject: {UserId} ({SubjectHash})")]
    public static partial void SessionRegistered(this ILogger logger, string sessionIdHash, string userId, string subjectHash);

    [LoggerMessage(EventId = 13807, Level = LogLevel.Error,
        Message = "Failed to retrieve sessions for email {Email} ({EmailHash})")]
    public static partial void GetSessionsByEmailError(this ILogger logger, string email, string emailHash, Exception ex);

    [LoggerMessage(EventId = 13808, Level = LogLevel.Error,
        Message = "Failed to terminate session {SessionIdHash}")]
    public static partial void TerminateSessionError(this ILogger logger, string sessionIdHash, Exception ex);

    [LoggerMessage(EventId = 13809, Level = LogLevel.Error,
        Message = "Failed to terminate sessions for email {Email} ({EmailHash})")]
    public static partial void TerminateSessionsByEmailError(this ILogger logger, string email, string emailHash, Exception ex);

    [LoggerMessage(EventId = 13810, Level = LogLevel.Error,
        Message = "Failed to add to email index for {NormalizedEmail} ({EmailHash})")]
    public static partial void AddToEmailIndexError(this ILogger logger, string normalizedEmail, string emailHash, Exception ex);

    [LoggerMessage(EventId = 13811, Level = LogLevel.Error,
        Message = "Failed to remove from email index for {NormalizedEmail} ({EmailHash})")]
    public static partial void RemoveFromEmailIndexError(this ILogger logger, string normalizedEmail, string emailHash, Exception ex);

    [LoggerMessage(EventId = 13812, Level = LogLevel.Warning,
        Message = "Failed to update refresh token on session metadata for {SessionIdHash}")]
    public static partial void UpdateRefreshTokenError(this ILogger logger, string sessionIdHash, Exception ex);

    [LoggerMessage(EventId = 13813, Level = LogLevel.Debug,
        Message = "Skipping IdP-side revocation for {SessionIdHash}: ITokenRevocationService is not registered")]
    public static partial void TokenRevocationServiceNotConfigured(this ILogger logger, string sessionIdHash);

    [LoggerMessage(EventId = 13814, Level = LogLevel.Debug,
        Message = "Skipping IdP-side revocation for {SessionIdHash}: IDataProtectionProvider is not registered")]
    public static partial void RevocationProtectorNotConfigured(this ILogger logger, string sessionIdHash);

    [LoggerMessage(EventId = 13815, Level = LogLevel.Debug,
        Message = "Skipping IdP-side revocation for {SessionIdHash}: no encrypted refresh token on metadata")]
    public static partial void NoRefreshTokenStored(this ILogger logger, string sessionIdHash);

    [LoggerMessage(EventId = 13816, Level = LogLevel.Warning,
        Message = "Failed to decrypt refresh token for session {SessionIdHash} (data protection key rotation?)")]
    public static partial void RefreshTokenDecryptFailed(this ILogger logger, string sessionIdHash, Exception ex);

    [LoggerMessage(EventId = 13817, Level = LogLevel.Warning,
        Message = "IdP returned non-success for refresh token revocation; session {SessionIdHash}")]
    public static partial void RefreshTokenRevocationReturnedFalse(this ILogger logger, string sessionIdHash);

    [LoggerMessage(EventId = 13818, Level = LogLevel.Debug,
        Message = "Failed to touch session metadata for {SessionIdHash}")]
    public static partial void TouchSessionFailed(this ILogger logger, string sessionIdHash, Exception ex);

    [LoggerMessage(EventId = 13819, Level = LogLevel.Debug,
        Message = "Failed to read session metadata for {SessionIdHash} (cache miss or deserialization error)")]
    public static partial void GetSessionMetadataFailed(this ILogger logger, string sessionIdHash, Exception ex);

    [LoggerMessage(EventId = 13820, Level = LogLevel.Debug,
        Message = "SessionExists check failed for {SessionIdHash}")]
    public static partial void SessionExistsCheckFailed(this ILogger logger, string sessionIdHash, Exception ex);

    [LoggerMessage(EventId = 13821, Level = LogLevel.Debug,
        Message = "Failed to read email index for {NormalizedEmail} ({EmailHash})")]
    public static partial void GetEmailIndexFailed(this ILogger logger, string normalizedEmail, string emailHash, Exception ex);

    [LoggerMessage(EventId = 13822, Level = LogLevel.Warning,
        Message = "Subject input is null or empty")]
    public static partial void SubjectInputInvalid(this ILogger logger);

    [LoggerMessage(EventId = 13823, Level = LogLevel.Information,
        Message = "Terminated {Count} sessions for subject: {Subject} ({SubjectHash})")]
    public static partial void SessionsTerminatedForSubject(this ILogger logger, int count, string subject, string subjectHash);

    [LoggerMessage(EventId = 13824, Level = LogLevel.Error,
        Message = "Failed to terminate sessions for subject {Subject} ({SubjectHash})")]
    public static partial void TerminateSessionsBySubjectError(this ILogger logger, string subject, string subjectHash, Exception ex);

    [LoggerMessage(EventId = 13825, Level = LogLevel.Debug,
        Message = "Failed to read subject index for {Subject} ({SubjectHash})")]
    public static partial void GetSubjectIndexFailed(this ILogger logger, string subject, string subjectHash, Exception ex);

    [LoggerMessage(EventId = 13826, Level = LogLevel.Error,
        Message = "Failed to add to subject index for {Subject} ({SubjectHash})")]
    public static partial void AddToSubjectIndexError(this ILogger logger, string subject, string subjectHash, Exception ex);

    [LoggerMessage(EventId = 13827, Level = LogLevel.Error,
        Message = "Failed to remove from subject index for {Subject} ({SubjectHash})")]
    public static partial void RemoveFromSubjectIndexError(this ILogger logger, string subject, string subjectHash, Exception ex);

    [LoggerMessage(EventId = 13828, Level = LogLevel.Warning,
        Message = "Distributed index lock timed out for {IndexKey}; skipping atomic update - under heavy contention an admin revocation may miss this session")]
    public static partial void IndexLockTimedOut(this ILogger logger, string indexKey);

    [LoggerMessage(EventId = 13829, Level = LogLevel.Warning,
        Message = "Email index update failed for session {SessionIdHash}; session remains revocable via subject (sub) index")]
    public static partial void RegisterSessionEmailIndexFailed(this ILogger logger, string sessionIdHash, Exception ex);

    [LoggerMessage(EventId = 13830, Level = LogLevel.Debug,
        Message = "Best-effort session metadata rollback cleanup failed ({ExceptionType}); original registration error is rethrown")]
    public static partial void SessionMetadataRollbackCleanupFailed(this ILogger logger, string exceptionType);
}
