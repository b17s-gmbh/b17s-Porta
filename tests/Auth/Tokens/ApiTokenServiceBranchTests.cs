using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Auth.Tokens;

/// <summary>
/// Branch coverage for <see cref="ApiTokenService"/>. The existing
/// <c>ApiTokenServiceTests</c> exercises one path (cached + expired + refresh succeeds).
/// These tests cover the remaining branches — fail-closed on missing inputs, cache-hit
/// short-circuit, the three "fall through to fresh exchange" paths (no cached token /
/// no refresh token / refresh returns null), the missing-OIDC-config branch in
/// BuildRefreshOptions, the preserve-old-refresh-token branch when the IdP doesn't
/// rotate, and the InvalidateApiTokensAsync overloads.
/// </summary>
public sealed class ApiTokenServiceBranchTests
{
    private const string CacheKey = "porta.api_access_token";

    // -----------------------------
    // Fail-closed: missing access token
    // -----------------------------

    [Fact]
    public async Task GetApiTokenAsync_NullAccessToken_ReturnsNullWithoutTouchingStorageOrExchange()
    {
        // Forwarding "Authorization: Bearer " (empty value) is silently treated as anonymous
        // by many backends — so we must fail closed rather than return "".
        var storage = new InMemoryTokenStorage();
        var exchange = new RecordingExchangeService(TokenExchangeResult.Failure("must-not-be-called"));
        var sut = CreateSut(storage, exchangeService: exchange);

        var result = await sut.GetApiTokenAsync(
            new DefaultHttpContext(),
            CreateApiConfig(),
            accessToken: null,
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Null(result);
        Assert.Equal(0, exchange.CallCount);
        // Storage was never read (no Get/Set calls); the key is absent and remains absent.
        Assert.Equal(0, storage.GetObjectCallCount);
    }

    [Fact]
    public async Task GetApiTokenAsync_EmptyAccessToken_ReturnsNullWithoutTouchingStorageOrExchange()
    {
        var storage = new InMemoryTokenStorage();
        var exchange = new RecordingExchangeService(TokenExchangeResult.Failure("must-not-be-called"));
        var sut = CreateSut(storage, exchangeService: exchange);

        var result = await sut.GetApiTokenAsync(
            new DefaultHttpContext(),
            CreateApiConfig(),
            accessToken: "",
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Null(result);
        Assert.Equal(0, exchange.CallCount);
    }

    // -----------------------------
    // Cache hit short-circuit
    // -----------------------------

    [Fact]
    public async Task GetApiTokenAsync_CacheHit_StillValid_ReturnsCachedTokenWithoutCallingExchangeOrRefresh()
    {
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        var apiConfig = CreateApiConfig();
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);

        var cached = new TokenExchangeResponse
        {
            AccessToken = "cached-access",
            RefreshToken = "cached-refresh",
            ExpiresIn = 3600,
            IssuedAt = clock.GetUtcNow(),
        };
        await storage.SetObjectAsync(httpContext, CacheKey, new Dictionary<string, TokenExchangeResponse>
        {
            [apiConfig.ApiPath] = cached,
        });

        var exchange = new RecordingExchangeService(TokenExchangeResult.Failure("exchange must not be called"));
        var refresh = new RecordingRefreshService(response: null);
        var sut = CreateSut(storage, exchangeService: exchange, refreshService: refresh, timeProvider: clock);

        var result = await sut.GetApiTokenAsync(
            httpContext,
            apiConfig,
            "user-token",
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Equal("cached-access", result);
        Assert.Equal(0, exchange.CallCount);
        Assert.Equal(0, refresh.CallCount);
    }

    // -----------------------------
    // Cache miss → fresh exchange
    // -----------------------------

    [Fact]
    public async Task GetApiTokenAsync_CacheMiss_PerformsExchangeAndCachesResult()
    {
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        var apiConfig = CreateApiConfig();
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);

        var freshResponse = new TokenExchangeResponse
        {
            AccessToken = "fresh-from-exchange",
            RefreshToken = "fresh-refresh",
            ExpiresIn = 3600,
        };
        var exchange = new RecordingExchangeService(TokenExchangeResult.Success(freshResponse));
        var refresh = new RecordingRefreshService(response: null);
        var sut = CreateSut(storage, exchangeService: exchange, refreshService: refresh, timeProvider: clock);

        var result = await sut.GetApiTokenAsync(
            httpContext,
            apiConfig,
            "user-token",
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Equal("fresh-from-exchange", result);
        Assert.Equal(1, exchange.CallCount);
        Assert.Equal(0, refresh.CallCount);

        // Result must have been cached, with IssuedAt stamped at the current TimeProvider value
        // so subsequent calls hit the cache.
        var cache = await storage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(httpContext, CacheKey);
        Assert.NotNull(cache);
        Assert.True(cache!.TryGetValue(apiConfig.ApiPath, out var stored));
        Assert.Equal("fresh-from-exchange", stored!.AccessToken);
        Assert.Equal(clock.GetUtcNow(), stored.IssuedAt);
    }

    [Fact]
    public async Task GetApiTokenAsync_CacheKeyExistsButNoEntryForThisApiPath_PerformsFreshExchange()
    {
        // The cache dictionary is shared across all API paths in the user's session. A miss for
        // this specific apiConfig.ApiPath must not be confused with "the whole cache is empty";
        // we still need to take the fresh-exchange path without touching the other entry.
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        var apiConfig = CreateApiConfig("/api/orders");
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);

        await storage.SetObjectAsync(httpContext, CacheKey, new Dictionary<string, TokenExchangeResponse>
        {
            // Entry for a different API path that must remain untouched.
            ["/api/billing"] = new() { AccessToken = "billing-token", ExpiresIn = 3600, IssuedAt = clock.GetUtcNow() },
        });

        var freshResponse = new TokenExchangeResponse { AccessToken = "orders-fresh", ExpiresIn = 3600 };
        var sut = CreateSut(storage,
            exchangeService: new RecordingExchangeService(TokenExchangeResult.Success(freshResponse)),
            timeProvider: clock);

        var result = await sut.GetApiTokenAsync(
            httpContext, apiConfig, "user-token",
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Equal("orders-fresh", result);
        var cache = await storage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(httpContext, CacheKey);
        Assert.Equal("billing-token", cache!["/api/billing"].AccessToken);
        Assert.Equal("orders-fresh", cache["/api/orders"].AccessToken);
    }

    // -----------------------------
    // Expired cache → refresh paths
    // -----------------------------

    [Fact]
    public async Task GetApiTokenAsync_ExpiredCachedToken_NoRefreshToken_FallsThroughToExchange()
    {
        // The refresh path is gated on cachedToken.RefreshToken being non-empty. When it's
        // missing we must skip refresh and go straight to exchange — refreshing without a
        // refresh token would call the IdP with grant_type=refresh_token&refresh_token=
        // and earn a 400.
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        var apiConfig = CreateApiConfig();
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);

        var expired = new TokenExchangeResponse
        {
            AccessToken = "expired",
            RefreshToken = "", // <-- the critical field
            ExpiresIn = 3600,
            IssuedAt = clock.GetUtcNow().AddHours(-2),
        };
        await storage.SetObjectAsync(httpContext, CacheKey, new Dictionary<string, TokenExchangeResponse>
        {
            [apiConfig.ApiPath] = expired,
        });

        var freshResponse = new TokenExchangeResponse { AccessToken = "via-exchange", ExpiresIn = 3600 };
        var exchange = new RecordingExchangeService(TokenExchangeResult.Success(freshResponse));
        var refresh = new RecordingRefreshService(response: null); // would throw if called via record

        var sut = CreateSut(storage, exchangeService: exchange, refreshService: refresh, timeProvider: clock);
        var result = await sut.GetApiTokenAsync(
            httpContext, apiConfig, "user-token",
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Equal("via-exchange", result);
        Assert.Equal(1, exchange.CallCount);
        Assert.Equal(0, refresh.CallCount);
    }

    [Fact]
    public async Task GetApiTokenAsync_ExpiredCachedToken_RefreshConfigIncomplete_InvalidatesAndExchanges()
    {
        // BuildRefreshOptions returns null when any of TokenEndpoint/ClientId/ClientSecret is
        // missing. In that case the code must invalidate this API's stale entry (only this
        // API's — other APIs' valid tokens stay) and fall back to fresh exchange — not
        // silently keep using the expired entry.
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        var apiConfig = new ApiConfiguration
        {
            ApiPath = "/api/orders",
            ApiScopes = "orders.read",
            ApiAudience = "orders-api",
            // TokenEndpoint / ClientId / ClientSecret all omitted -> BuildRefreshOptions returns null.
        };
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);

        var expired = new TokenExchangeResponse
        {
            AccessToken = "expired",
            RefreshToken = "stored-refresh-token",
            ExpiresIn = 3600,
            IssuedAt = clock.GetUtcNow().AddHours(-2),
        };
        await storage.SetObjectAsync(httpContext, CacheKey, new Dictionary<string, TokenExchangeResponse>
        {
            [apiConfig.ApiPath] = expired,
            ["/api/other"] = new() { AccessToken = "other-valid", ExpiresIn = 3600, IssuedAt = clock.GetUtcNow() },
        });

        var freshResponse = new TokenExchangeResponse { AccessToken = "via-exchange", ExpiresIn = 3600 };
        var exchange = new RecordingExchangeService(TokenExchangeResult.Success(freshResponse));
        var refresh = new RecordingRefreshService(response: null); // must not be called

        var sut = CreateSut(storage, exchangeService: exchange, refreshService: refresh, timeProvider: clock);
        var result = await sut.GetApiTokenAsync(
            httpContext, apiConfig, "user-token",
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Equal("via-exchange", result);
        Assert.Equal(0, refresh.CallCount);
        Assert.Equal(1, exchange.CallCount);

        // Only the failed entry was dropped (then re-populated by the exchange);
        // the other API's still-valid token survived.
        var cache = await storage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(httpContext, CacheKey);
        Assert.NotNull(cache);
        Assert.Equal("via-exchange", cache![apiConfig.ApiPath].AccessToken);
        Assert.Equal("other-valid", cache["/api/other"].AccessToken);
    }

    [Fact]
    public async Task GetApiTokenAsync_ExpiredCachedToken_RefreshReturnsNull_InvalidatesAndExchanges()
    {
        // When TokenRefreshService returns null (IdP said no, or threw and was swallowed
        // upstream), the failed API's entry must be invalidated and we must fall back to a
        // fresh exchange. Without invalidation, the next call would loop on the same stale
        // entry — but other APIs' still-valid tokens in the same dictionary must survive.
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        var apiConfig = CreateApiConfig();
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);

        await storage.SetObjectAsync(httpContext, CacheKey, new Dictionary<string, TokenExchangeResponse>
        {
            [apiConfig.ApiPath] = new()
            {
                AccessToken = "expired",
                RefreshToken = "stored-refresh-token",
                ExpiresIn = 3600,
                IssuedAt = clock.GetUtcNow().AddHours(-2),
            },
            ["/api/other"] = new() { AccessToken = "other-valid", ExpiresIn = 3600, IssuedAt = clock.GetUtcNow() },
        });

        var refresh = new RecordingRefreshService(response: null); // refresh returns null
        var freshResponse = new TokenExchangeResponse { AccessToken = "via-exchange-after-failed-refresh", ExpiresIn = 3600 };
        var exchange = new RecordingExchangeService(TokenExchangeResult.Success(freshResponse));

        var sut = CreateSut(storage, exchangeService: exchange, refreshService: refresh, timeProvider: clock);
        var result = await sut.GetApiTokenAsync(
            httpContext, apiConfig, "user-token",
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Equal("via-exchange-after-failed-refresh", result);
        Assert.Equal(1, refresh.CallCount);
        Assert.Equal(1, exchange.CallCount);

        // A single API's refresh failure must not discard every other API's token.
        var cache = await storage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(httpContext, CacheKey);
        Assert.NotNull(cache);
        Assert.Equal("via-exchange-after-failed-refresh", cache![apiConfig.ApiPath].AccessToken);
        Assert.Equal("other-valid", cache["/api/other"].AccessToken);
    }

    [Fact]
    public async Task GetApiTokenAsync_ExpiredCachedToken_RefreshSuccessWithoutRotatedRefreshToken_PreservesOldRefreshToken()
    {
        // OAuth refresh-token rotation is optional. When the IdP returns a refresh response
        // with an empty refresh_token, the cached refresh token must be preserved so future
        // refreshes still work — overwriting it with "" would prevent the next refresh.
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        var apiConfig = CreateApiConfig();
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);

        var originalRefresh = "stored-refresh-token";
        await storage.SetObjectAsync(httpContext, CacheKey, new Dictionary<string, TokenExchangeResponse>
        {
            [apiConfig.ApiPath] = new()
            {
                AccessToken = "expired",
                RefreshToken = originalRefresh,
                ExpiresIn = 3600,
                IssuedAt = clock.GetUtcNow().AddHours(-2),
            },
        });

        var refresh = new RecordingRefreshService(new TokenExchangeResponse
        {
            AccessToken = "fresh-from-refresh",
            RefreshToken = "", // <-- IdP did not rotate
            ExpiresIn = 3600,
        });
        var exchange = new RecordingExchangeService(TokenExchangeResult.Failure("exchange must not be called"));

        var sut = CreateSut(storage, exchangeService: exchange, refreshService: refresh, timeProvider: clock);
        var result = await sut.GetApiTokenAsync(
            httpContext, apiConfig, "user-token",
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Equal("fresh-from-refresh", result);

        var cache = await storage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(httpContext, CacheKey);
        Assert.NotNull(cache);
        var stored = cache![apiConfig.ApiPath];
        Assert.Equal("fresh-from-refresh", stored.AccessToken);
        Assert.Equal(originalRefresh, stored.RefreshToken); // preserved, not overwritten with ""
        Assert.Equal(clock.GetUtcNow(), stored.IssuedAt);
        Assert.Equal(0, exchange.CallCount);
    }

    [Fact]
    public async Task GetApiTokenAsync_ExpiredCachedToken_RefreshSuccessWithRotatedRefreshToken_OverwritesCachedRefreshToken()
    {
        // The other side of the rotation switch: when the IdP does rotate, we must overwrite
        // the old refresh token. Otherwise the next refresh would use a token the IdP just
        // invalidated (Keycloak, Auth0 rotation mode, etc.).
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        var apiConfig = CreateApiConfig();
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);

        await storage.SetObjectAsync(httpContext, CacheKey, new Dictionary<string, TokenExchangeResponse>
        {
            [apiConfig.ApiPath] = new()
            {
                AccessToken = "expired",
                RefreshToken = "original-refresh",
                ExpiresIn = 3600,
                IssuedAt = clock.GetUtcNow().AddHours(-2),
            },
        });

        var refresh = new RecordingRefreshService(new TokenExchangeResponse
        {
            AccessToken = "fresh-access",
            RefreshToken = "rotated-refresh",
            ExpiresIn = 3600,
        });

        var sut = CreateSut(storage, refreshService: refresh, timeProvider: clock);
        var result = await sut.GetApiTokenAsync(
            httpContext, apiConfig, "user-token",
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Equal("fresh-access", result);
        var cache = await storage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(httpContext, CacheKey);
        Assert.Equal("rotated-refresh", cache![apiConfig.ApiPath].RefreshToken);
    }

    // -----------------------------
    // Fresh exchange failure
    // -----------------------------

    [Fact]
    public async Task GetApiTokenAsync_ExchangeFails_ReturnsNullWithoutCaching()
    {
        // Fail-closed contract from the interface docs: callers MUST treat null as
        // "could not obtain a token". The cache must not be polluted with a failure.
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        var apiConfig = CreateApiConfig();

        var exchange = new RecordingExchangeService(TokenExchangeResult.Failure("idp said no"));
        var sut = CreateSut(storage, exchangeService: exchange);

        var result = await sut.GetApiTokenAsync(
            httpContext, apiConfig, "user-token",
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        Assert.Null(result);
        var cache = await storage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(httpContext, CacheKey);
        Assert.Null(cache); // no SetObject call happened
    }

    // -----------------------------
    // Invalidate overloads
    // -----------------------------

    [Fact]
    public async Task InvalidateApiTokensAsync_ExplicitCacheOptions_RemovesObjectAtCacheKey()
    {
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        await storage.SetObjectAsync(httpContext, CacheKey, new Dictionary<string, TokenExchangeResponse>
        {
            ["/api/orders"] = new() { AccessToken = "x", ExpiresIn = 3600 },
        });

        var sut = CreateSut(storage);
        await sut.InvalidateApiTokensAsync(
            httpContext,
            new ApiTokenCacheOptions { CacheKey = CacheKey },
            TestContext.Current.CancellationToken);

        var cache = await storage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(httpContext, CacheKey);
        Assert.Null(cache);
    }

    [Fact]
    public async Task InvalidateApiTokensAsync_SessionConfigOverload_DerivesCacheKeyFromSessionAuthConfig()
    {
        // The no-arg overload picks the cache key from SessionAuthenticationConfiguration.
        // Verify that's the same key the no-arg GetApiTokenAsync would write to, otherwise
        // get/invalidate would point at different storage locations.
        var sessionAuthConfig = new SessionAuthenticationConfiguration();
        var derivedKey = sessionAuthConfig.SessionKeys.GetApiAccessTokenKey();

        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        await storage.SetObjectAsync(httpContext, derivedKey, new Dictionary<string, TokenExchangeResponse>
        {
            ["/api/orders"] = new() { AccessToken = "x", ExpiresIn = 3600 },
        });

        var sut = CreateSut(storage, sessionAuthConfig: sessionAuthConfig);
        await sut.InvalidateApiTokensAsync(httpContext, TestContext.Current.CancellationToken);

        var cache = await storage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(httpContext, derivedKey);
        Assert.Null(cache);
    }

    [Fact]
    public async Task GetApiTokenAsync_SessionConfigOverload_UsesSessionConfigDerivedKey()
    {
        // The no-arg overload is the production-path overload — the explicit one is for callers
        // who want to avoid the SessionAuthenticationConfiguration coupling. Both must end up
        // writing to the same cache key for a given SessionAuthenticationConfiguration.
        var sessionAuthConfig = new SessionAuthenticationConfiguration();
        var derivedKey = sessionAuthConfig.SessionKeys.GetApiAccessTokenKey();

        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();
        var apiConfig = CreateApiConfig();

        var freshResponse = new TokenExchangeResponse { AccessToken = "via-default-overload", ExpiresIn = 3600 };
        var sut = CreateSut(storage,
            exchangeService: new RecordingExchangeService(TokenExchangeResult.Success(freshResponse)),
            sessionAuthConfig: sessionAuthConfig);

        var result = await sut.GetApiTokenAsync(
            httpContext, apiConfig, "user-token", TestContext.Current.CancellationToken);

        Assert.Equal("via-default-overload", result);
        var cache = await storage.GetObjectAsync<Dictionary<string, TokenExchangeResponse>>(httpContext, derivedKey);
        Assert.NotNull(cache);
        Assert.Equal("via-default-overload", cache![apiConfig.ApiPath].AccessToken);
    }

    // ===========================================================================
    // Helpers
    // ===========================================================================

    private static ApiTokenService CreateSut(
        ITokenStorage storage,
        ITokenExchangeService? exchangeService = null,
        ITokenRefreshService? refreshService = null,
        SessionAuthenticationConfiguration? sessionAuthConfig = null,
        TimeProvider? timeProvider = null)
    {
        return new ApiTokenService(
            exchangeService ?? new RecordingExchangeService(TokenExchangeResult.Failure("exchange not configured for this test")),
            refreshService ?? new RecordingRefreshService(response: null),
            storage,
            Options.Create(sessionAuthConfig ?? new SessionAuthenticationConfiguration()),
            Options.Create(new PortaCoreOptions()),
            NullLogger<ApiTokenService>.Instance,
            timeProvider);
    }

    private static ApiConfiguration CreateApiConfig(string apiPath = "/api/orders") => new()
    {
        ApiPath = apiPath,
        ApiScopes = "orders.read",
        ApiAudience = "orders-api",
        ClientId = "orders-client",
        ClientSecret = "orders-secret",
        TokenEndpoint = "https://idp.test/connect/token",
    };

    private sealed class RecordingExchangeService(TokenExchangeResult result) : ITokenExchangeService
    {
        public int CallCount { get; private set; }

        public Task<TokenExchangeResult> ExchangeAsync(string accessToken, ApiConfiguration apiConfig, CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult(result);
        }
    }

    private sealed class RecordingRefreshService(TokenExchangeResponse? response) : ITokenRefreshService
    {
        public int CallCount { get; private set; }

        public Task<RefreshTokenResult> RefreshAsync(string refreshToken, TokenRefreshOptions options, CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult(response is { } r ? RefreshTokenResult.Success(r) : RefreshTokenResult.Transient());
        }

        public Task<RefreshTokenResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("ApiTokenService should always pass explicit refresh options.");
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class InMemoryTokenStorage : ITokenStorage
    {
        private readonly Dictionary<string, string> _strings = new();
        private readonly Dictionary<string, object> _objects = new();

        public int GetObjectCallCount { get; private set; }
        public int SetObjectCallCount { get; private set; }
        public int RemoveObjectCallCount { get; private set; }

        public Task<string?> GetTokenAsync(HttpContext context, string key)
            => Task.FromResult(_strings.TryGetValue(key, out var v) ? v : null);

        public Task<bool> SetTokenAsync(HttpContext context, string key, string value)
        {
            _strings[key] = value;
            return Task.FromResult(true);
        }

        public Task RemoveTokenAsync(HttpContext context, string key)
        {
            _strings.Remove(key);
            return Task.CompletedTask;
        }

        public Task<T?> GetObjectAsync<T>(HttpContext context, string key) where T : class
        {
            GetObjectCallCount++;
            return Task.FromResult(_objects.TryGetValue(key, out var v) ? v as T : null);
        }

        public Task<bool> SetObjectAsync<T>(HttpContext context, string key, T value) where T : class
        {
            SetObjectCallCount++;
            _objects[key] = value;
            return Task.FromResult(true);
        }

        public Task RemoveObjectAsync(HttpContext context, string key)
        {
            RemoveObjectCallCount++;
            _objects.Remove(key);
            return Task.CompletedTask;
        }

        public Task<bool> ClearAllAsync(HttpContext context)
        {
            _strings.Clear();
            _objects.Clear();
            return Task.FromResult(true);
        }
    }
}
