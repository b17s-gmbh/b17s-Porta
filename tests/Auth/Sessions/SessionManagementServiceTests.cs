using System.Security.Claims;
using System.Text.Json;

using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Auth.Sessions;

public class SessionManagementServiceTests
{
    private const string MetadataPrefix = "porta:session_meta:";

    [Fact]
    public async Task RegisterSessionAsync_WithEncryptedRefreshToken_PersistsItOnMetadata()
    {
        var (svc, cache) = CreateService();

        await svc.RegisterSessionAsync(
            sessionId: "sid-1",
            userId: "user-1",
            email: "user@example.com",
            ipAddress: "1.2.3.4",
            userAgent: "test",
            encryptedRefreshToken: "ENCRYPTED-RT");

        var stored = await cache.GetStringAsync(MetadataPrefix + "sid-1", TestContext.Current.CancellationToken);
        Assert.NotNull(stored);
        var roundTripped = JsonSerializer.Deserialize<SessionInfo>(stored!);
        Assert.NotNull(roundTripped);
        Assert.Equal("ENCRYPTED-RT", roundTripped!.EncryptedRefreshToken);
        Assert.Equal("user-1", roundTripped.UserId);
        Assert.Equal("user@example.com", roundTripped.Email);
    }

    [Fact]
    public async Task RegisterSessionAsync_WithoutToken_LeavesEncryptedRefreshTokenNull()
    {
        var (svc, cache) = CreateService();

        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com");

        var stored = await cache.GetStringAsync(MetadataPrefix + "sid-1", TestContext.Current.CancellationToken);
        var roundTripped = JsonSerializer.Deserialize<SessionInfo>(stored!);
        Assert.Null(roundTripped!.EncryptedRefreshToken);
    }

    [Fact]
    public async Task UpdateRefreshTokenAsync_PatchesExistingMetadata()
    {
        var (svc, cache) = CreateService();
        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com", encryptedRefreshToken: "OLD-RT");

        await svc.UpdateRefreshTokenAsync("sid-1", "NEW-RT");

        var stored = await cache.GetStringAsync(MetadataPrefix + "sid-1", TestContext.Current.CancellationToken);
        var roundTripped = JsonSerializer.Deserialize<SessionInfo>(stored!);
        Assert.Equal("NEW-RT", roundTripped!.EncryptedRefreshToken);
    }

    [Fact]
    public async Task UpdateRefreshTokenAsync_ClearsToken_WhenPassedNull()
    {
        var (svc, cache) = CreateService();
        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com", encryptedRefreshToken: "OLD-RT");

        await svc.UpdateRefreshTokenAsync("sid-1", null);

        var stored = await cache.GetStringAsync(MetadataPrefix + "sid-1", TestContext.Current.CancellationToken);
        var roundTripped = JsonSerializer.Deserialize<SessionInfo>(stored!);
        Assert.Null(roundTripped!.EncryptedRefreshToken);
    }

    [Fact]
    public async Task UpdateRefreshTokenAsync_NoExistingMetadata_NoOps()
    {
        var (svc, cache) = CreateService();

        await svc.UpdateRefreshTokenAsync("missing-sid", "RT");

        // No write should have happened.
        var stored = await cache.GetStringAsync(MetadataPrefix + "missing-sid", TestContext.Current.CancellationToken);
        Assert.Null(stored);
    }

    [Fact]
    public async Task UpdateRefreshTokenAsync_EmptySessionId_NoOps()
    {
        var (svc, _) = CreateService();
        // Should not throw.
        await svc.UpdateRefreshTokenAsync(string.Empty, "RT");
    }

    [Fact]
    public async Task TerminateSessionAsync_RevokeTokensTrue_DecryptsAndCallsRevocation()
    {
        var (svc, cache, revocation) = CreateServiceWithRevocation();
        var encrypted = svc.ProtectRefreshToken("real-refresh-token");
        Assert.NotNull(encrypted);
        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com", encryptedRefreshToken: encrypted);

        var success = await svc.TerminateSessionAsync("sid-1", revokeTokens: true, TestContext.Current.CancellationToken);

        Assert.True(success);
        Assert.Equal(1, revocation.Calls);
        Assert.Equal("real-refresh-token", revocation.LastToken);
        Assert.Equal("refresh_token", revocation.LastHint);
    }

    [Fact]
    public async Task TerminateSessionAsync_RevokeTokensFalse_DoesNotCallRevocation()
    {
        var (svc, _, revocation) = CreateServiceWithRevocation();
        var encrypted = svc.ProtectRefreshToken("real-refresh-token");
        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com", encryptedRefreshToken: encrypted);

        var success = await svc.TerminateSessionAsync("sid-1", revokeTokens: false, TestContext.Current.CancellationToken);

        Assert.True(success);
        Assert.Equal(0, revocation.Calls);
    }

    [Fact]
    public async Task TerminateSessionAsync_RemovesAuthTicket_FromTicketStore()
    {
        // Wire a real ticket store into the session service and verify that
        // termination wipes the ticket - not just the metadata. Regression for
        // the cache-key mismatch where TerminateSessionAsync called
        // cache.RemoveAsync(sessionId) instead of going through ITicketStore,
        // leaving the ticket (and therefore the cookie) live.
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var protector = new EphemeralDataProtectionProvider();
        var ticketStore = new DistributedCacheTicketStore(
            cache,
            protector,
            Options.Create(new TicketStoreOptions()),
            NullLogger<DistributedCacheTicketStore>.Instance);
        var config = new SessionAuthenticationConfiguration { SessionTimeoutInMin = 60 };
        var svc = new SessionManagementService(
            cache,
            Options.Create(config),
            NullLogger<SessionManagementService>.Instance,
            ticketStore: ticketStore);

        // Store a ticket under the same id used at session registration.
        var identity = new ClaimsIdentity(authenticationType: CookieAuthenticationDefaults.AuthenticationScheme);
        identity.AddClaim(new Claim("sub", "user-1"));
        var ticket = new AuthenticationTicket(
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1) },
            CookieAuthenticationDefaults.AuthenticationScheme);
        ticket.Properties.Items[".bff.session_id"] = "sid-1";
        var key = await ticketStore.StoreAsync(ticket);
        Assert.Equal("sid-1", key);

        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com");
        Assert.NotNull(await ticketStore.RetrieveAsync("sid-1"));

        var success = await svc.TerminateSessionAsync("sid-1", revokeTokens: false, TestContext.Current.CancellationToken);

        Assert.True(success);
        Assert.Null(await ticketStore.RetrieveAsync("sid-1"));
    }

    [Fact]
    public async Task TerminateSessionAsync_NoEncryptedToken_StillSucceeds()
    {
        var (svc, _, revocation) = CreateServiceWithRevocation();
        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com", encryptedRefreshToken: null);

        var success = await svc.TerminateSessionAsync("sid-1", revokeTokens: true, TestContext.Current.CancellationToken);

        // Local termination still completes; revocation just no-ops.
        Assert.True(success);
        Assert.Equal(0, revocation.Calls);
    }

    [Fact]
    public async Task TerminateSessionAsync_DecryptFailureWithDifferentKeys_StillSucceeds()
    {
        // Register with one protector...
        var protectorA = new EphemeralDataProtectionProvider();
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var config = new SessionAuthenticationConfiguration { SessionTimeoutInMin = 60 };
        var revocation = new RecordingRevocationService();
        var svcA = new SessionManagementService(cache, Options.Create(config), NullLogger<SessionManagementService>.Instance, tokenRevocationService: revocation, dataProtectionProvider: protectorA);
        var encrypted = svcA.ProtectRefreshToken("real-refresh-token");
        await svcA.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com", encryptedRefreshToken: encrypted);

        // ...then attempt revocation with a different protector (key rotation simulation).
        var protectorB = new EphemeralDataProtectionProvider();
        var svcB = new SessionManagementService(cache, Options.Create(config), NullLogger<SessionManagementService>.Instance, tokenRevocationService: revocation, dataProtectionProvider: protectorB);

        var success = await svcB.TerminateSessionAsync("sid-1", revokeTokens: true, TestContext.Current.CancellationToken);

        // Local termination still completes.
        Assert.True(success);
        // Revocation never fires because decryption failed.
        Assert.Equal(0, revocation.Calls);
    }

    [Fact]
    public async Task TerminateSessionAsync_NoRevocationService_LocalTerminationStillSucceeds()
    {
        // Service constructed without ITokenRevocationService.
        var (svc, _) = CreateService();
        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com");

        var success = await svc.TerminateSessionAsync("sid-1", revokeTokens: true, TestContext.Current.CancellationToken);

        Assert.True(success); // local cleanup still happens
    }

    [Fact]
    public void ProtectRefreshToken_NoDataProtector_ReturnsNull()
    {
        var (svc, _) = CreateService();
        Assert.Null(svc.ProtectRefreshToken("rt"));
    }

    [Fact]
    public void ProtectRefreshToken_NullOrEmptyInput_ReturnsNull()
    {
        var (svc, _, _) = CreateServiceWithRevocation();
        Assert.Null(svc.ProtectRefreshToken(null));
        Assert.Null(svc.ProtectRefreshToken(string.Empty));
    }

    [Fact]
    public void ProtectRefreshToken_RoundTripsThroughOwnProtector()
    {
        var (svc, _, _) = CreateServiceWithRevocation();
        var encrypted = svc.ProtectRefreshToken("plain-rt");
        Assert.NotNull(encrypted);
        Assert.NotEqual("plain-rt", encrypted);
    }

    [Fact]
    public async Task RegisterSessionAsync_RecordsCreatedAndIncrementsActiveGauge()
    {
        using var harness = b17s.Porta.Tests.Telemetry.RecordingMetricsHarness.Create();
        var (svc, _) = CreateService(harness.Metrics);

        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com");

        Assert.Single(harness.Drain("bff.session.created"));
        Assert.Equal(1, harness.Net("bff.sessions.active"));
    }

    [Fact]
    public async Task TerminateSessionAsync_RecordsInvalidatedWithReason_AndBalancesActiveGauge()
    {
        using var harness = b17s.Porta.Tests.Telemetry.RecordingMetricsHarness.Create();
        var (svc, _) = CreateService(harness.Metrics);
        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com");

        var terminated = await svc.TerminateSessionAsync("sid-1", revokeTokens: false, TestContext.Current.CancellationToken, reason: "logout");

        Assert.True(terminated);
        var invalidated = harness.Drain("bff.session.invalidated");
        Assert.Single(invalidated);
        Assert.Equal("logout", invalidated[0].Tags["reason"]);
        // created (+1) then invalidated (-1) nets the active gauge back to zero.
        Assert.Equal(0, harness.Net("bff.sessions.active"));
    }

    [Fact]
    public async Task TerminateSessionAsync_AbsentSession_DoesNotRecordInvalidated_NoDoubleDecrement()
    {
        // A terminate against an already-gone session id must not decrement the active gauge again:
        // the gauge is only incremented once per RegisterSessionAsync, so a spurious decrement here
        // would drift it negative.
        using var harness = b17s.Porta.Tests.Telemetry.RecordingMetricsHarness.Create();
        var (svc, _) = CreateService(harness.Metrics);

        var terminated = await svc.TerminateSessionAsync("never-registered", revokeTokens: false, TestContext.Current.CancellationToken, reason: "logout");

        Assert.True(terminated); // best-effort cleanup still reports success
        Assert.Empty(harness.Drain("bff.session.invalidated"));
        Assert.Equal(0, harness.Net("bff.sessions.active"));
    }

    [Fact]
    public async Task GetSessionsByEmailAsync_TicketCheckThrows_TreatsAsUnknown_DoesNotPrune()
    {
        // A transient cache error while verifying the ticket must not be read as "session
        // gone" - that would permanently remove a live session from the email index, making
        // admin terminate-by-email silently miss it forever (report L2).
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var config = new SessionAuthenticationConfiguration { SessionTimeoutInMin = 60 };
        var store = new FlakyTicketStore();
        var svc = new SessionManagementService(cache, Options.Create(config), NullLogger<SessionManagementService>.Instance, ticketStore: store);
        store.Seed("sid-1");
        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com");

        store.ThrowOnRetrieve = true;
        var duringOutage = await svc.GetSessionsByEmailAsync("user@example.com", TestContext.Current.CancellationToken);

        store.ThrowOnRetrieve = false;
        var afterRecovery = await svc.GetSessionsByEmailAsync("user@example.com", TestContext.Current.CancellationToken);

        Assert.Single(duringOutage); // unknown is still reported, not hidden
        Assert.Single(afterRecovery); // and crucially, never pruned from the index
    }

    [Fact]
    public async Task GetSessionsByEmailAsync_TicketDefinitelyGone_StillPrunesFromIndex()
    {
        // The L2 fix must not break legitimate cleanup: a definite "ticket absent" verdict
        // (store reachable, no ticket) still prunes the dead id from the email index.
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var config = new SessionAuthenticationConfiguration { SessionTimeoutInMin = 60 };
        var store = new FlakyTicketStore(); // never seeded -> RetrieveAsync returns null
        var svc = new SessionManagementService(cache, Options.Create(config), NullLogger<SessionManagementService>.Instance, ticketStore: store);
        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com");

        var sessions = await svc.GetSessionsByEmailAsync("user@example.com", TestContext.Current.CancellationToken);

        Assert.Empty(sessions);
        Assert.Null(await cache.GetStringAsync("porta:email_sessions:user@example.com", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TerminateSessionsBySubject_DeadIndexEntry_NotCounted_AndPruned()
    {
        // Ids whose metadata already expired must not inflate "Terminated N sessions", and
        // must be pruned so the subject index doesn't accumulate dead ids forever (report L4).
        var (svc, cache) = CreateService();
        await svc.RegisterSessionAsync("sid-live", userId: "user-1");
        await svc.RegisterSessionAsync("sid-dead", userId: "user-1");
        // Simulate sid-dead's metadata expiring while its subject index entry lingers.
        await cache.RemoveAsync(MetadataPrefix + "sid-dead", TestContext.Current.CancellationToken);

        var count = await svc.TerminateSessionsBySubjectAsync("user-1", revokeTokens: false, TestContext.Current.CancellationToken);

        Assert.Equal(1, count);
        // Live id removed by its termination, dead id by the prune: index empty and deleted.
        Assert.Null(await cache.GetStringAsync("porta:sub_sessions:user-1", TestContext.Current.CancellationToken));
        // Second sweep finds nothing left to count.
        Assert.Equal(0, await svc.TerminateSessionsBySubjectAsync("user-1", revokeTokens: false, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RegisterSessionAsync_PopulatesExpiresAt_FromCookieTicketLifetime()
    {
        // ExpiresAt mirrors the cookie ticket lifetime so the admin API reports a real
        // expiry instead of the perpetual null it shipped with (report L3).
        var now = new DateTimeOffset(2026, 6, 10, 12, 0, 0, TimeSpan.Zero);
        var clock = new FakeTimeProvider(now);
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var config = new SessionAuthenticationConfiguration
        {
            SessionTimeoutInMin = 60,
            Cookie = new CookieSecurityConfiguration { ExpireTimeSpanMinutes = 90 },
        };
        var svc = new SessionManagementService(cache, Options.Create(config), NullLogger<SessionManagementService>.Instance, timeProvider: clock);

        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com");

        var stored = JsonSerializer.Deserialize<SessionInfo>(
            (await cache.GetStringAsync(MetadataPrefix + "sid-1", TestContext.Current.CancellationToken))!);
        Assert.Equal(now.AddMinutes(90), stored!.ExpiresAt);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TouchSessionAsync_SlidesExpiresAt_OnlyWithSlidingExpiration(bool sliding)
    {
        var start = new DateTimeOffset(2026, 6, 10, 12, 0, 0, TimeSpan.Zero);
        var clock = new FakeTimeProvider(start);
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var config = new SessionAuthenticationConfiguration
        {
            SessionTimeoutInMin = 60,
            Cookie = new CookieSecurityConfiguration { ExpireTimeSpanMinutes = 60, SlidingExpiration = sliding },
        };
        var svc = new SessionManagementService(cache, Options.Create(config), NullLogger<SessionManagementService>.Instance, timeProvider: clock);
        await svc.RegisterSessionAsync("sid-1", userId: "user-1");

        clock.Now = start.AddMinutes(30);
        await svc.TouchSessionAsync("sid-1");

        var stored = JsonSerializer.Deserialize<SessionInfo>(
            (await cache.GetStringAsync(MetadataPrefix + "sid-1", TestContext.Current.CancellationToken))!);
        var expected = sliding ? start.AddMinutes(90) : start.AddMinutes(60);
        Assert.Equal(expected, stored!.ExpiresAt);
    }

    // Pins the H1 invariant: metadata and the sub/email revocation indexes must not be
    // able to expire while the cookie ticket is still alive. Their sliding window is
    // max(SessionTimeoutInMin, Cookie.ExpireTimeSpanMinutes) - at least one full cookie
    // lifetime, which is the longest a live ticket can go between renewals (the renewal
    // slides these entries via DistributedCacheTicketStore.RenewAsync).
    [Theory]
    [InlineData(30, 480, 480)] // cookie lifetime longer than session timeout -> cookie lifetime wins
    [InlineData(600, 60, 600)] // session timeout acts as a floor when longer
    public async Task RegisterSessionAsync_IndexAndMetadataTtl_CoversCookieTicketLifetime(
        int sessionTimeoutMin, int cookieExpireMin, int expectedTtlMin)
    {
        var cache = new SetOptionsRecordingCache(new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())));
        var config = new SessionAuthenticationConfiguration
        {
            SessionTimeoutInMin = sessionTimeoutMin,
            Cookie = new CookieSecurityConfiguration { ExpireTimeSpanMinutes = cookieExpireMin },
        };
        var svc = new SessionManagementService(cache, Options.Create(config), NullLogger<SessionManagementService>.Instance);

        await svc.RegisterSessionAsync("sid-1", userId: "user-1", email: "user@example.com");

        var expected = TimeSpan.FromMinutes(expectedTtlMin);
        Assert.Equal(expected, cache.LastSetOptions["porta:session_meta:sid-1"].SlidingExpiration);
        Assert.Equal(expected, cache.LastSetOptions["porta:sub_sessions:user-1"].SlidingExpiration);
        Assert.Equal(expected, cache.LastSetOptions["porta:email_sessions:user@example.com"].SlidingExpiration);
    }

    private sealed class SetOptionsRecordingCache(IDistributedCache inner) : IDistributedCache
    {
        public Dictionary<string, DistributedCacheEntryOptions> LastSetOptions { get; } = [];

        public byte[]? Get(string key) => inner.Get(key);
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => inner.GetAsync(key, token);
        public void Refresh(string key) => inner.Refresh(key);
        public Task RefreshAsync(string key, CancellationToken token = default) => inner.RefreshAsync(key, token);
        public void Remove(string key) => inner.Remove(key);
        public Task RemoveAsync(string key, CancellationToken token = default) => inner.RemoveAsync(key, token);

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            LastSetOptions[key] = options;
            inner.Set(key, value, options);
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            LastSetOptions[key] = options;
            return inner.SetAsync(key, value, options, token);
        }
    }

    private static (SessionManagementService svc, IDistributedCache cache) CreateService(PortaMetrics? metrics = null)
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var config = new SessionAuthenticationConfiguration { SessionTimeoutInMin = 60 };
        var svc = new SessionManagementService(cache, Options.Create(config), NullLogger<SessionManagementService>.Instance, metrics: metrics);
        return (svc, cache);
    }

    private static (SessionManagementService svc, IDistributedCache cache, RecordingRevocationService revocation) CreateServiceWithRevocation()
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var config = new SessionAuthenticationConfiguration { SessionTimeoutInMin = 60 };
        var revocation = new RecordingRevocationService();
        var protector = new EphemeralDataProtectionProvider();
        var svc = new SessionManagementService(cache, Options.Create(config), NullLogger<SessionManagementService>.Instance, tokenRevocationService: revocation, dataProtectionProvider: protector);
        return (svc, cache, revocation);
    }

    /// <summary>
    /// Ticket store whose RetrieveAsync can be toggled to throw, modelling a transient
    /// distributed-cache outage during the SessionExists liveness check.
    /// </summary>
    private sealed class FlakyTicketStore : ITicketStore
    {
        private readonly Dictionary<string, AuthenticationTicket> _tickets = new(StringComparer.Ordinal);

        public bool ThrowOnRetrieve { get; set; }

        public void Seed(string key) => _tickets[key] = new AuthenticationTicket(
            new ClaimsPrincipal(new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme)),
            CookieAuthenticationDefaults.AuthenticationScheme);

        public Task<string> StoreAsync(AuthenticationTicket ticket) => throw new NotSupportedException();
        public Task RenewAsync(string key, AuthenticationTicket ticket) => Task.CompletedTask;

        public Task<AuthenticationTicket?> RetrieveAsync(string key) => ThrowOnRetrieve
            ? throw new InvalidOperationException("cache outage")
            : Task.FromResult(_tickets.GetValueOrDefault(key));

        public Task RemoveAsync(string key)
        {
            _tickets.Remove(key);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class RecordingRevocationService : ITokenRevocationService
    {
        public int Calls { get; private set; }
        public string? LastToken { get; private set; }
        public string? LastHint { get; private set; }
        public bool ReturnValue { get; set; } = true;

        public Task<bool> RevokeTokenAsync(string token, TokenRevocationOptions options, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
            => RecordAndReturn(token, tokenTypeHint);
        public Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
            => RecordAndReturn(token, tokenTypeHint);
        public Task<TokenRevocationBatchResult> RevokeTokensAsync(TokenRevocationOptions options, CancellationToken cancellationToken, params (string Token, string? TokenTypeHint)[] tokens)
            => Task.FromResult(BuildBatch(tokens));
        public Task<TokenRevocationBatchResult> RevokeTokensAsync(CancellationToken cancellationToken, params (string Token, string? TokenTypeHint)[] tokens)
            => Task.FromResult(BuildBatch(tokens));

        private TokenRevocationBatchResult BuildBatch((string Token, string? TokenTypeHint)[] tokens)
            => new() { Outcomes = tokens.Select(t => new TokenRevocationOutcome(t.TokenTypeHint, ReturnValue)).ToList() };

        private Task<bool> RecordAndReturn(string token, string? hint)
        {
            Calls++;
            LastToken = token;
            LastHint = hint;
            return Task.FromResult(ReturnValue);
        }
    }
}
