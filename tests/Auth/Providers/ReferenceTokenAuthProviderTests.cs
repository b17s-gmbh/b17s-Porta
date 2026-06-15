using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Services;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Auth.Providers;

public class ReferenceTokenAuthProviderTests
{
    private const string SampleToken = "abc.def.ghi-secret-token";

    [Fact]
    public void BuildIntrospectionCacheKey_DoesNotContainRawToken()
    {
        var key = ReferenceTokenAuthProvider.BuildIntrospectionCacheKey(SampleToken);

        Assert.StartsWith("introspection_", key);
        Assert.DoesNotContain(SampleToken, key);
    }

    [Fact]
    public void BuildIntrospectionCacheKey_UsesSha256HexDigest()
    {
        var expectedDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(SampleToken)));

        var key = ReferenceTokenAuthProvider.BuildIntrospectionCacheKey(SampleToken);

        Assert.Equal($"introspection_{expectedDigest}", key);
    }

    [Fact]
    public void BuildIntrospectionCacheKey_IsDeterministic()
    {
        var key1 = ReferenceTokenAuthProvider.BuildIntrospectionCacheKey(SampleToken);
        var key2 = ReferenceTokenAuthProvider.BuildIntrospectionCacheKey(SampleToken);

        Assert.Equal(key1, key2);
    }

    [Fact]
    public void BuildIntrospectionCacheKey_DifferentTokensProduceDifferentKeys()
    {
        var key1 = ReferenceTokenAuthProvider.BuildIntrospectionCacheKey("token-one");
        var key2 = ReferenceTokenAuthProvider.BuildIntrospectionCacheKey("token-two");

        Assert.NotEqual(key1, key2);
    }

    [Fact]
    public void IntrospectionResponse_DeserialisesSingleStringAud()
    {
        const string json = """{"active":true,"aud":"single-aud"}""";

        var response = JsonSerializer.Deserialize<IntrospectionResponse>(json);

        Assert.NotNull(response);
        Assert.NotNull(response!.Aud);
        Assert.Equal(["single-aud"], response.Aud);
    }

    [Fact]
    public void IntrospectionResponse_DeserialisesArrayAud()
    {
        const string json = """{"active":true,"aud":["aud-a","aud-b"]}""";

        var response = JsonSerializer.Deserialize<IntrospectionResponse>(json);

        Assert.NotNull(response);
        Assert.NotNull(response!.Aud);
        Assert.Equal(["aud-a", "aud-b"], response.Aud);
    }

    [Fact]
    public void IntrospectionResponse_DeserialisesMissingAudAsNull()
    {
        const string json = """{"active":true}""";

        var response = JsonSerializer.Deserialize<IntrospectionResponse>(json);

        Assert.NotNull(response);
        Assert.Null(response!.Aud);
    }

    [Fact]
    public void AudienceContainsAny_MatchesSingleAudience()
    {
        Assert.True(InvokeAudienceContainsAny("expected", ["expected"]));
        Assert.False(InvokeAudienceContainsAny("other", ["expected"]));
    }

    [Fact]
    public void AudienceContainsAny_MatchesAnyOfArrayAudience()
    {
        var encoded = JsonSerializer.Serialize(new[] { "first", "second" });

        Assert.True(InvokeAudienceContainsAny(encoded, ["second"]));
        Assert.True(InvokeAudienceContainsAny(encoded, ["first", "third"]));
        Assert.False(InvokeAudienceContainsAny(encoded, ["third"]));
    }

    [Fact]
    public void AudienceContainsAny_TreatsNonJsonValueAsBareString()
    {
        // A bare string starting with '[' must not be sniffed as JSON.
        Assert.True(InvokeAudienceContainsAny("[not-json", ["[not-json"]));
    }

    private static bool InvokeAudienceContainsAny(string audClaim, IList<string> expected)
    {
        var method = typeof(ReferenceTokenAuthenticator).GetMethod(
            "AudienceContainsAny",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        return (bool)method.Invoke(null, [audClaim, expected, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance])!;
    }
}

/// <summary>
/// Behavioural tests for <see cref="ReferenceTokenAuthProvider.GetAuthContextAsync"/> and
/// <see cref="ReferenceTokenAuthProvider.InvalidateAsync"/>. These exercise the cache
/// hit/miss paths, binding validation, negative caching, and cache-duration calculation
/// — the security-critical surface that the static helper tests don't reach.
/// </summary>
public sealed class ReferenceTokenAuthProviderFlowTests
{
    private const string Token = "ref-token-123";
    private const string Bearer = "Bearer " + Token;

    [Fact]
    public async Task NoAuthorizationHeader_ReturnsUnauthenticated_WithoutIntrospecting()
    {
        var introspector = new FakeIntrospector();
        var sut = Build(introspector, new ReferenceTokenAuthOptions());

        var ctx = await sut.GetAuthContextAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken);

        Assert.False(ctx.IsAuthenticated);
        Assert.Equal(0, introspector.CallCount);
    }

    [Fact]
    public async Task WrongPrefix_ReturnsUnauthenticated_WithoutIntrospecting()
    {
        // A Basic-auth-style header must not be treated as a reference token.
        var introspector = new FakeIntrospector();
        var sut = Build(introspector, new ReferenceTokenAuthOptions());
        var httpContext = WithAuthHeader("Basic dXNlcjpwYXNz");

        var ctx = await sut.GetAuthContextAsync(httpContext, TestContext.Current.CancellationToken);

        Assert.False(ctx.IsAuthenticated);
        Assert.Equal(0, introspector.CallCount);
    }

    [Theory]
    [InlineData("bearer " + Token)]
    [InlineData("BEARER " + Token)]
    public async Task TokenPrefix_MatchedCaseInsensitively_PerRfc7235(string header)
    {
        // RFC 7235 auth scheme names are case-insensitive; "bearer x" must authenticate
        // exactly like "Bearer x" (and the match must be ordinal, not culture-sensitive).
        var introspector = new FakeIntrospector(_ => Active(claims: new() { ["sub"] = "alice" }));
        var sut = Build(introspector, OptionsFor(validateAudience: false, validateIssuer: false));

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(header), TestContext.Current.CancellationToken);

        Assert.True(ctx.IsAuthenticated);
        Assert.Equal(Token, ctx.AccessToken);
    }

    [Fact]
    public async Task ValidToken_IntrospectsAndPopulatesContext_AndCachesResult()
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var introspector = new FakeIntrospector(_ => Active(claims: new() { ["sub"] = "alice", ["aud"] = "bff" }));
        var options = OptionsFor(validateAudience: false, validateIssuer: false);
        var sut = Build(introspector, options, cache);

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.True(ctx.IsAuthenticated);
        Assert.Equal(Token, ctx.AccessToken);
        Assert.Equal("alice", ctx.Claims["sub"][0]);

        // Second call must be served from cache without re-introspecting.
        var cached = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);
        Assert.True(cached.IsAuthenticated);
        Assert.Equal(1, introspector.CallCount);
    }

    [Fact]
    public async Task InactiveToken_CachesNegativeResult_AndShortCircuitsSubsequentCalls()
    {
        // Negative cache exists to stop attacker token-spray from amplifying IdP traffic;
        // verify it actually short-circuits.
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var introspector = new FakeIntrospector(_ => new ReferenceTokenIntrospectionResult { IsActive = false });
        var sut = Build(introspector, OptionsFor(), cache);

        var first = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);
        var second = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.False(first.IsAuthenticated);
        Assert.False(second.IsAuthenticated);
        Assert.Equal(1, introspector.CallCount);
    }

    [Fact]
    public async Task NegativeCacheDisabled_RehitsIntrospectionEachCall()
    {
        // NegativeCacheDuration == Zero is the documented opt-out.
        var introspector = new FakeIntrospector(_ => new ReferenceTokenIntrospectionResult { IsActive = false });
        var options = OptionsFor();
        options.NegativeCacheDuration = TimeSpan.Zero;
        var sut = Build(introspector, options);

        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);
        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.Equal(2, introspector.CallCount);
    }

    [Fact]
    public async Task IntrospectionUnavailable_FailsClosed_AndDoesNotNegativeCache()
    {
        // IntrospectTokenAsync returns null when introspection produced no answer (IdP 5xx
        // after retries, missing endpoint, oversized body). That must not be negative-cached:
        // an IdP outage would otherwise reject a VALID token for NegativeCacheDuration.
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var introspector = new FakeIntrospector(_ => null);
        var sut = Build(introspector, OptionsFor(), cache);

        var first = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);
        var second = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.False(first.IsAuthenticated);
        Assert.False(second.IsAuthenticated);
        // No negative cache entry was written, so the second call re-introspects —
        // the token authenticates again as soon as the IdP recovers.
        Assert.Equal(2, introspector.CallCount);
        var stored = await cache.GetStringAsync(
            ReferenceTokenAuthProvider.BuildIntrospectionCacheKey(Token),
            TestContext.Current.CancellationToken);
        Assert.Null(stored);
    }

    [Fact]
    public async Task IntrospectionException_FailsClosed_AndDoesNotCache()
    {
        // Network blips or 5xx from the IdP must not authenticate the request, and must
        // not poison the cache — the next request gets a fresh attempt.
        var introspector = new FakeIntrospector(_ => throw new HttpRequestException("boom"));
        var sut = Build(introspector, OptionsFor());

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);
        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.False(ctx.IsAuthenticated);
        Assert.Equal(2, introspector.CallCount);
    }

    [Fact]
    public async Task IntrospectionCanceled_PropagatesInsteadOfFailingClosed()
    {
        // Cooperative cancellation (request abort, shutdown) must propagate per the provider
        // contract - not be laundered into an "introspection error" unauthenticated context.
        using var cts = new CancellationTokenSource();
        var introspector = new FakeIntrospector(_ =>
        {
            // Model the request aborting mid-introspection.
            cts.Cancel();
            throw new OperationCanceledException(cts.Token);
        });
        var sut = Build(introspector, OptionsFor());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sut.GetAuthContextAsync(WithAuthHeader(Bearer), cts.Token));
    }

    [Fact]
    public async Task CorruptCacheEntry_IsEvicted_AndFallsThroughToIntrospection()
    {
        // Old cache shape / partial write must not lock everyone out of login until TTL.
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var options = OptionsFor(validateAudience: false, validateIssuer: false);
        var key = ReferenceTokenAuthProvider.BuildIntrospectionCacheKey(Token);
        await cache.SetStringAsync(key, "{not valid json", TestContext.Current.CancellationToken);

        var introspector = new FakeIntrospector(_ => Active());
        var sut = Build(introspector, options, cache);

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.True(ctx.IsAuthenticated);
        Assert.Equal(1, introspector.CallCount);
    }

    [Fact]
    public async Task ValidateAudience_RejectsTokenWhenAudAndClientIdDoNotMatch()
    {
        // The whole point of audience binding: an "active" token from the same IdP for a
        // different relying party must NOT authenticate this BFF.
        var introspector = new FakeIntrospector(_ => Active(new() { ["aud"] = "some-other-rp", ["client_id"] = "other-app" }));
        var options = OptionsFor(validateIssuer: false);
        options.ValidAudiences = ["this-bff"];
        options.ValidClientIds = ["this-bff-client"];
        var sut = Build(introspector, options);

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.False(ctx.IsAuthenticated);
        Assert.Empty(ctx.Claims);
    }

    [Fact]
    public async Task ValidateAudience_AcceptsTokenWhenAudMatches()
    {
        var introspector = new FakeIntrospector(_ => Active(new() { ["aud"] = "this-bff" }));
        var options = OptionsFor(validateIssuer: false);
        options.ValidAudiences = ["this-bff"];
        var sut = Build(introspector, options);

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.True(ctx.IsAuthenticated);
    }

    [Fact]
    public async Task ValidateAudience_AcceptsTokenWhenClientIdMatches_EvenIfAudMissing()
    {
        // The OR logic: some IdPs return client_id instead of aud on introspection.
        var introspector = new FakeIntrospector(_ => Active(new() { ["client_id"] = "trusted-client" }));
        var options = OptionsFor(validateIssuer: false);
        options.ValidAudiences = ["this-bff"];
        options.ValidClientIds = ["trusted-client"];
        var sut = Build(introspector, options);

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.True(ctx.IsAuthenticated);
    }

    [Fact]
    public async Task ValidateAudience_AcceptsTokenWhenAudIsJsonArrayContainingMatch()
    {
        var introspector = new FakeIntrospector(_ => Active(new()
        {
            ["aud"] = JsonSerializer.Serialize(new[] { "other-rp", "this-bff" }),
        }));
        var options = OptionsFor(validateIssuer: false);
        options.ValidAudiences = ["this-bff"];
        var sut = Build(introspector, options);

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.True(ctx.IsAuthenticated);
    }

    [Fact]
    public async Task ValidateIssuer_RejectsTokenWhenIssMissing()
    {
        var introspector = new FakeIntrospector(_ => Active(new() { ["aud"] = "this-bff" }));
        var options = OptionsFor(validateAudience: false);
        options.ValidIssuers = ["https://idp.test/"];
        var sut = Build(introspector, options);

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.False(ctx.IsAuthenticated);
    }

    [Fact]
    public async Task ValidateIssuer_RejectsTokenWhenIssDoesNotMatch()
    {
        var introspector = new FakeIntrospector(_ => Active(new() { ["iss"] = "https://attacker.test/" }));
        var options = OptionsFor(validateAudience: false);
        options.ValidIssuers = ["https://idp.test/"];
        var sut = Build(introspector, options);

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.False(ctx.IsAuthenticated);
    }

    [Fact]
    public async Task ValidateIssuer_AllowsTokenWhenIssMatchesAuthority_AndValidIssuersIsEmpty()
    {
        // Fallback path when only Authority is configured.
        var introspector = new FakeIntrospector(_ => Active(new() { ["iss"] = "https://idp.test/" }));
        var options = OptionsFor(validateAudience: false);
        options.Authority = "https://idp.test/";
        var sut = Build(introspector, options);

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.True(ctx.IsAuthenticated);
    }

    [Fact]
    public async Task ValidateIssuer_IsByteForByte_TrailingSlashMustMatchExactly()
    {
        // Documented behaviour: trailing-slash mismatches are a config bug surfaced here.
        var introspector = new FakeIntrospector(_ => Active(new() { ["iss"] = "https://idp.test" }));
        var options = OptionsFor(validateAudience: false);
        options.ValidIssuers = ["https://idp.test/"];
        var sut = Build(introspector, options);

        var ctx = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.False(ctx.IsAuthenticated);
    }

    [Fact]
    public async Task RejectedBinding_CachesNegativeResult()
    {
        // The rejected-by-binding path must also short-circuit subsequent calls so a token
        // for the wrong audience can't be used to spray the IdP either.
        var introspector = new FakeIntrospector(_ => Active(new() { ["aud"] = "other-rp" }));
        var options = OptionsFor(validateIssuer: false);
        options.ValidAudiences = ["this-bff"];
        var sut = Build(introspector, options);

        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);
        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.Equal(1, introspector.CallCount);
    }

    [Fact]
    public async Task InvalidateAsync_RemovesCachedEntry_SoNextCallReintrospects()
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var introspector = new FakeIntrospector(_ => Active());
        var sut = Build(introspector, OptionsFor(validateAudience: false, validateIssuer: false), cache);

        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);
        await sut.InvalidateAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);
        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.Equal(2, introspector.CallCount);
    }

    [Fact]
    public async Task InvalidateAsync_WithoutAuthHeader_IsNoOp()
    {
        var sut = Build(new FakeIntrospector(), new ReferenceTokenAuthOptions());
        await sut.InvalidateAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken);
        // No throw is the assertion.
    }

    [Fact]
    public async Task CacheDuration_FloorIs10Seconds_WhenIntrospectedExpiryIsImminent()
    {
        // result.ExpiresAt is "now" — the calculation produces a negative number, the
        // floor must clamp to 10s rather than persisting a zero/negative TTL that
        // backends interpret variously.
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-05-20T00:00:00Z"));
        var introspector = new FakeIntrospector(_ => Active(expiresAt: time.GetUtcNow()));
        var cache = new RecordingDistributedCache();
        var sut = Build(introspector, OptionsFor(validateAudience: false, validateIssuer: false), cache, time);

        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.NotNull(cache.LastSetOptions);
        Assert.Equal(TimeSpan.FromSeconds(10), cache.LastSetOptions!.AbsoluteExpirationRelativeToNow);
    }

    [Fact]
    public async Task CacheDuration_CapsAtMaxCacheDuration_WhenTokenExpiryIsFarOut()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-05-20T00:00:00Z"));
        var introspector = new FakeIntrospector(_ => Active(expiresAt: time.GetUtcNow().AddDays(7)));
        var cache = new RecordingDistributedCache();
        var options = OptionsFor(validateAudience: false, validateIssuer: false);
        options.MaxCacheDuration = TimeSpan.FromMinutes(15);
        var sut = Build(introspector, options, cache, time);

        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.NotNull(cache.LastSetOptions);
        Assert.Equal(TimeSpan.FromMinutes(15), cache.LastSetOptions!.AbsoluteExpirationRelativeToNow);
    }

    [Fact]
    public async Task CacheDuration_FallsBackToDefault_WhenExpiresAtMissing()
    {
        var introspector = new FakeIntrospector(_ => Active(expiresAt: null));
        var cache = new RecordingDistributedCache();
        var options = OptionsFor(validateAudience: false, validateIssuer: false);
        options.DefaultCacheDuration = TimeSpan.FromMinutes(7);
        var sut = Build(introspector, options, cache);

        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.Equal(TimeSpan.FromMinutes(7), cache.LastSetOptions!.AbsoluteExpirationRelativeToNow);
    }

    [Fact]
    public async Task CacheDuration_UsesTokenExpiryMinusSkewBuffer_WhenWithinBounds()
    {
        // Expiry 10 minutes out, minus 30s buffer = 9m30s. Below MaxCacheDuration (1h)
        // and above 10s floor, so the calculated value is used as-is.
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-05-20T00:00:00Z"));
        var introspector = new FakeIntrospector(_ => Active(expiresAt: time.GetUtcNow().AddMinutes(10)));
        var cache = new RecordingDistributedCache();
        var sut = Build(introspector, OptionsFor(validateAudience: false, validateIssuer: false), cache, time);

        await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.Equal(TimeSpan.FromMinutes(10) - TimeSpan.FromSeconds(30), cache.LastSetOptions!.AbsoluteExpirationRelativeToNow);
    }

    [Fact]
    public async Task RefreshAsync_AlwaysReturnsNull()
    {
        // Documented behaviour: reference tokens are introspected each time, not refreshed.
        var sut = Build(new FakeIntrospector(), new ReferenceTokenAuthOptions());
        var result = await sut.RefreshAsync(new AuthenticationContext(), TestContext.Current.CancellationToken);
        Assert.Null(result);
    }

    [Fact]
    public async Task OptionsMonitorReload_TakesEffectImmediately()
    {
        // Reading CurrentValue per call (rather than capturing options at ctor time) is
        // the documented requirement so secret rotation / audience adds don't need a
        // process restart.
        var introspector = new FakeIntrospector(_ => Active(new() { ["aud"] = "new-aud" }));
        var monitor = new ToggleOptionsMonitor<ReferenceTokenAuthOptions>(
            OptionsFor(validateAudience: true, validateIssuer: false));
        monitor.Current.ValidAudiences = ["old-aud"];

        var sut = new ReferenceTokenAuthProvider(BuildAuthenticator(introspector, monitor));

        var rejected = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);
        Assert.False(rejected.IsAuthenticated);

        monitor.Current.ValidAudiences = ["new-aud"];
        // Use a different token so we bypass the negative cache from the first call.
        var accepted = await sut.GetAuthContextAsync(
            WithAuthHeader("Bearer other-token"),
            TestContext.Current.CancellationToken);
        Assert.True(accepted.IsAuthenticated);
    }

    [Fact]
    public async Task PositiveCacheEntry_RevalidatesBindingAgainstTightenedOptions()
    {
        // A token accepted and positively cached under a permissive policy must NOT keep
        // authenticating after ValidAudiences is tightened - binding is re-checked on every
        // cache hit against CurrentValue, not just on the introspection cache miss.
        var introspector = new FakeIntrospector(_ => Active(new() { ["aud"] = "old-aud" }));
        var monitor = new ToggleOptionsMonitor<ReferenceTokenAuthOptions>(
            OptionsFor(validateAudience: true, validateIssuer: false));
        monitor.Current.ValidAudiences = ["old-aud"];

        var sut = new ReferenceTokenAuthProvider(BuildAuthenticator(introspector, monitor));

        // First call: accepted under the old policy and written to the positive cache.
        var accepted = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);
        Assert.True(accepted.IsAuthenticated);
        Assert.Equal(1, introspector.CallCount);

        // Tighten the policy so the cached token's audience is no longer allowed. The same
        // token now hits the positive cache entry, so the binding re-check is what must reject it.
        monitor.Current.ValidAudiences = ["new-aud"];
        var rejected = await sut.GetAuthContextAsync(WithAuthHeader(Bearer), TestContext.Current.CancellationToken);

        Assert.False(rejected.IsAuthenticated);
        Assert.Null(rejected.AccessToken);
        Assert.Empty(rejected.Claims);
        // No re-introspection: the verdict came from the cache hit, rejected by binding alone.
        Assert.Equal(1, introspector.CallCount);
    }

    // ---------- helpers ----------

    private static ReferenceTokenAuthProvider Build(
        IReferenceTokenService introspector,
        ReferenceTokenAuthOptions options,
        IDistributedCache? cache = null,
        TimeProvider? timeProvider = null) =>
        new(BuildAuthenticator(
            introspector,
            new StaticOptionsMonitor<ReferenceTokenAuthOptions>(options),
            cache,
            timeProvider));

    private static ReferenceTokenAuthenticator BuildAuthenticator(
        IReferenceTokenService introspector,
        IOptionsMonitor<ReferenceTokenAuthOptions> monitor,
        IDistributedCache? cache = null,
        TimeProvider? timeProvider = null) =>
        new(
            introspector,
            cache ?? new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            NullLogger<ReferenceTokenAuthenticator>.Instance,
            monitor,
            timeProvider);

    private static ReferenceTokenAuthOptions OptionsFor(
        bool validateAudience = true,
        bool validateIssuer = true) => new()
        {
            ValidateAudience = validateAudience,
            ValidateIssuer = validateIssuer,
        };

    private static HttpContext WithAuthHeader(string value)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = value;
        return ctx;
    }

    private static ReferenceTokenIntrospectionResult Active(
        Dictionary<string, string>? claims = null,
        DateTimeOffset? expiresAt = null) => new()
        {
            IsActive = true,
            ExpiresAt = expiresAt,
            Claims = claims ?? [],
        };

    private sealed class FakeIntrospector : IReferenceTokenService
    {
        private readonly Func<string, ReferenceTokenIntrospectionResult?> _onCall;

        public int CallCount { get; private set; }

        public FakeIntrospector() : this(_ => null) { }
        public FakeIntrospector(Func<string, ReferenceTokenIntrospectionResult?> onCall) => _onCall = onCall;

        public Task<ReferenceTokenIntrospectionResult?> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult(_onCall(token));
        }
    }

    private sealed class RecordingDistributedCache : IDistributedCache
    {
        private readonly Dictionary<string, byte[]> _store = new(StringComparer.Ordinal);

        public DistributedCacheEntryOptions? LastSetOptions { get; private set; }

        public byte[]? Get(string key) => _store.GetValueOrDefault(key);
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult(Get(key));

        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;

        public void Remove(string key) => _store.Remove(key);
        public Task RemoveAsync(string key, CancellationToken token = default) { Remove(key); return Task.CompletedTask; }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            _store[key] = value;
            LastSetOptions = options;
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Set(key, value, options);
            return Task.CompletedTask;
        }
    }

    private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class ToggleOptionsMonitor<T>(T initial) : IOptionsMonitor<T> where T : class
    {
        public T Current { get; set; } = initial;
        public T CurrentValue => Current;
        public T Get(string? name) => Current;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
    }
}
