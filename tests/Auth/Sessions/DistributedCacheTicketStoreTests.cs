using System.Security.Claims;

using b17s.Porta.Auth.Sessions;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Auth.Sessions;

public class DistributedCacheTicketStoreTests
{
    [Fact]
    public async Task StoreAsync_GeneratesKeyAndPersistsTicket()
    {
        var (store, _) = CreateStore();
        var ticket = MakeTicket(sub: "user-1");

        var key = await store.StoreAsync(ticket);

        Assert.NotNull(key);
        Assert.NotEmpty(key);
        var roundTripped = await store.RetrieveAsync(key);
        Assert.NotNull(roundTripped);
        Assert.Equal("user-1", roundTripped!.Principal.FindFirst("sub")?.Value);
    }

    [Fact]
    public async Task RetrieveAsync_UnknownKey_ReturnsNull()
    {
        var (store, _) = CreateStore();

        var result = await store.RetrieveAsync("does-not-exist");

        Assert.Null(result);
    }

    [Fact]
    public async Task RetrieveAsync_EmptyKey_ReturnsNull()
    {
        var (store, _) = CreateStore();

        var result = await store.RetrieveAsync(string.Empty);

        Assert.Null(result);
    }

    [Fact]
    public async Task RenewAsync_OverwritesExistingTicket()
    {
        var (store, _) = CreateStore();
        var key = await store.StoreAsync(MakeTicket(sub: "user-old"));

        await store.RenewAsync(key, MakeTicket(sub: "user-new"));

        var roundTripped = await store.RetrieveAsync(key);
        Assert.NotNull(roundTripped);
        Assert.Equal("user-new", roundTripped!.Principal.FindFirst("sub")?.Value);
    }

    [Fact]
    public async Task RemoveAsync_DeletesTicket()
    {
        var (store, _) = CreateStore();
        var key = await store.StoreAsync(MakeTicket(sub: "user-1"));

        await store.RemoveAsync(key);

        Assert.Null(await store.RetrieveAsync(key));
    }

    [Fact]
    public async Task StoredBlob_IsNotPlaintextSerializedTicket()
    {
        var (store, cache) = CreateStore();
        var key = await store.StoreAsync(MakeTicket(sub: "secret-user-id-9482"));

        // The cache holds the protected (encrypted) blob - it must not contain the
        // raw "sub" value as plaintext bytes.
        var raw = await cache.GetAsync("porta:auth_ticket:" + key, TestContext.Current.CancellationToken);
        Assert.NotNull(raw);

        var asString = System.Text.Encoding.UTF8.GetString(raw!);
        Assert.DoesNotContain("secret-user-id-9482", asString);
    }

    [Fact]
    public async Task StoreAsync_UsesBffSessionIdFromProperties_AsTicketKey()
    {
        var (store, cache) = CreateStore();
        var ticket = MakeTicket(sub: "user-1");
        ticket.Properties.Items[".bff.session_id"] = "sid-from-oidc";

        var key = await store.StoreAsync(ticket);

        Assert.Equal("sid-from-oidc", key);
        // And the ticket is addressable in the underlying cache under the prefixed key.
        var raw = await cache.GetAsync("porta:auth_ticket:sid-from-oidc", TestContext.Current.CancellationToken);
        Assert.NotNull(raw);
    }

    [Fact]
    public async Task StoreAsync_NoBffSessionIdInProperties_FallsBackToFreshGuid()
    {
        var (store, _) = CreateStore();
        var ticket = MakeTicket(sub: "user-1");
        // No .bff.session_id stashed.

        var key = await store.StoreAsync(ticket);

        Assert.False(string.IsNullOrEmpty(key));
        // 32-char hex (Guid "N" format).
        Assert.Equal(32, key.Length);
        Assert.True(Guid.TryParseExact(key, "N", out _));
    }

    [Fact]
    public async Task RetrieveAsync_DecryptFailure_ReturnsNullDoesNotThrow()
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var protectorA = new EphemeralDataProtectionProvider();
        var protectorB = new EphemeralDataProtectionProvider(); // different keys

        var optionsA = Options.Create(new TicketStoreOptions());
        var storeA = new DistributedCacheTicketStore(cache, protectorA, optionsA, NullLogger<DistributedCacheTicketStore>.Instance);
        var key = await storeA.StoreAsync(MakeTicket(sub: "user-1"));

        // Now try to read it back with a *different* protector - should fail to
        // decrypt and return null without throwing.
        var optionsB = Options.Create(new TicketStoreOptions());
        var storeB = new DistributedCacheTicketStore(cache, protectorB, optionsB, NullLogger<DistributedCacheTicketStore>.Instance);

        var result = await storeB.RetrieveAsync(key);

        Assert.Null(result);
    }

    private static (DistributedCacheTicketStore store, IDistributedCache cache) CreateStore()
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var protector = new EphemeralDataProtectionProvider();
        var options = Options.Create(new TicketStoreOptions());
        var store = new DistributedCacheTicketStore(cache, protector, options, NullLogger<DistributedCacheTicketStore>.Instance);
        return (store, cache);
    }

    private static AuthenticationTicket MakeTicket(string sub)
    {
        var identity = new ClaimsIdentity(authenticationType: "TestScheme");
        identity.AddClaim(new Claim("sub", sub));
        var principal = new ClaimsPrincipal(identity);
        var properties = new AuthenticationProperties();
        properties.ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1);
        return new AuthenticationTicket(principal, properties, "TestScheme");
    }
}
