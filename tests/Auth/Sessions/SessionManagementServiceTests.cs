using System.Security.Claims;
using System.Text.Json;

using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

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

    private static (SessionManagementService svc, IDistributedCache cache) CreateService()
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var config = new SessionAuthenticationConfiguration { SessionTimeoutInMin = 60 };
        var svc = new SessionManagementService(cache, Options.Create(config), NullLogger<SessionManagementService>.Instance);
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
