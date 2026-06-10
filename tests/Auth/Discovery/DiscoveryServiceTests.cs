using System.Net;
using System.Text;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Configuration;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace b17s.Porta.Tests.Auth.Discovery;

public sealed class DiscoveryServiceTests
{
    [Fact]
    public void BuildMetadataAddress_AppendsWellKnownPath()
    {
        Assert.Equal(
            "https://idp.test/.well-known/openid-configuration",
            DiscoveryService.BuildMetadataAddress("https://idp.test"));
    }

    [Fact]
    public void BuildMetadataAddress_PreservesTrailingSlash()
    {
        // IdPs differ on whether they advertise iss as "https://idp" or "https://idp/".
        // That exact string is what token validation compares against (RFC 7519), so the
        // metadata-address builder must preserve the configured form and only add the
        // missing separator - silently trimming the trailing slash would shift the drift
        // from configuration time to token-validation time.
        Assert.Equal(
            "https://idp.test/.well-known/openid-configuration",
            DiscoveryService.BuildMetadataAddress("https://idp.test/"));
    }

    [Fact]
    public void BuildMetadataAddress_PreservesPathSegments()
    {
        // Realm-style authorities ("https://idp/realms/my-realm") must keep the realm
        // path; just append the discovery suffix.
        Assert.Equal(
            "https://idp.test/realms/my/.well-known/openid-configuration",
            DiscoveryService.BuildMetadataAddress("https://idp.test/realms/my"));
    }

    [Fact]
    public async Task GetConfigurationAsync_NullAuthority_ReturnsNull_NoHttpCall()
    {
        // Null / empty authority must fail closed - no fetch, no manager cache entry.
        var handler = new RecordingHandler(_ => DiscoveryDocument());
        var sut = Build(handler);

        var result = await sut.GetConfigurationAsync(null!, TestContext.Current.CancellationToken);

        Assert.Null(result);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task GetConfigurationAsync_EmptyAuthority_ReturnsNull_NoHttpCall()
    {
        var handler = new RecordingHandler(_ => DiscoveryDocument());
        var sut = Build(handler);

        var result = await sut.GetConfigurationAsync("", TestContext.Current.CancellationToken);

        Assert.Null(result);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task GetConfigurationAsync_FetchesDiscoveryDocument()
    {
        var handler = new RecordingHandler(_ => DiscoveryDocument(issuer: "https://idp.test"));
        var sut = Build(handler);

        var result = await sut.GetConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.Equal("https://idp.test", result!.Issuer);
        // ConfigurationManager also fetches JWKS as part of the discovery flow;
        // we only care that it hit the metadata URL at least once.
        Assert.Contains(handler.RequestUris, u => u == "https://idp.test/.well-known/openid-configuration");
    }

    [Fact]
    public async Task GetConfigurationAsync_CachesConfigurationAcrossCalls()
    {
        // ConfigurationManager caches discovery internally; the second call should be
        // served from cache rather than re-fetching. If this regresses, every token
        // validation roundtrip would re-hit the IdP discovery endpoint.
        var handler = new RecordingHandler(_ => DiscoveryDocument(issuer: "https://idp.test"));
        var sut = Build(handler);

        await sut.GetConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);
        var callsAfterFirst = handler.RequestUris.Count;
        await sut.GetConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);

        Assert.Equal(callsAfterFirst, handler.RequestUris.Count);
    }

    [Fact]
    public async Task GetConfigurationAsync_DifferentAuthorities_GetSeparateManagers()
    {
        // Each authority gets its own ConfigurationManager (keyed by string). The
        // second authority must trigger a fresh fetch (we check the discovery URL,
        // not total call count, since each fetch also pulls JWKS).
        var handler = new RecordingHandler(req =>
        {
            var host = req.RequestUri!.Host;
            return DiscoveryDocument(issuer: $"https://{host}");
        });
        var sut = Build(handler);

        var resultA = await sut.GetConfigurationAsync("https://idp-a.test", TestContext.Current.CancellationToken);
        var resultB = await sut.GetConfigurationAsync("https://idp-b.test", TestContext.Current.CancellationToken);

        Assert.NotNull(resultA);
        Assert.NotNull(resultB);
        Assert.Equal("https://idp-a.test", resultA!.Issuer);
        Assert.Equal("https://idp-b.test", resultB!.Issuer);
        Assert.Contains(handler.RequestUris, u => u == "https://idp-a.test/.well-known/openid-configuration");
        Assert.Contains(handler.RequestUris, u => u == "https://idp-b.test/.well-known/openid-configuration");
    }

    [Fact]
    public async Task GetConfigurationAsync_FetchFailure_ReturnsNull_WithoutThrowing()
    {
        // Caller (introspection/validation) must keep running when the IdP discovery
        // endpoint is down - it'll fall back to whatever guarded behaviour the caller has.
        // Throwing here would 500 every protected request during an IdP outage.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var sut = Build(handler);

        var result = await sut.GetConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    [Fact]
    public async Task GetConfigurationAsync_NonHttpsAuthority_RejectedWhenRequireHttpsMetadataTrue()
    {
        // Default RequireHttpsMetadata=true should refuse to load a discovery doc
        // from an http:// authority. HttpDocumentRetriever enforces this and throws,
        // which the service swallows and returns null.
        var handler = new RecordingHandler(_ => DiscoveryDocument());
        var sut = Build(handler, new SessionAuthenticationConfiguration { RequireHttpsMetadata = true });

        var result = await sut.GetConfigurationAsync("http://idp.test", TestContext.Current.CancellationToken);

        Assert.Null(result);
        // Retriever blocks the call before any HTTP traffic.
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task GetConfigurationAsync_NonHttpsAuthority_AllowedWhenRequireHttpsMetadataFalse()
    {
        // Local-dev opt-out: with RequireHttpsMetadata=false the retriever should permit
        // plain-http discovery. Useful for testcontainers etc.
        var handler = new RecordingHandler(_ => DiscoveryDocument(issuer: "http://idp.test"));
        var sut = Build(handler, new SessionAuthenticationConfiguration { RequireHttpsMetadata = false });

        var result = await sut.GetConfigurationAsync("http://idp.test", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.Contains(handler.RequestUris, u => u == "http://idp.test/.well-known/openid-configuration");
    }

    [Fact]
    public async Task GetConfigurationAsync_Cancellation_Propagates_NotSwallowedAsNull()
    {
        // A caller-cancelled token (request abort / host shutdown) must surface as cancellation,
        // not be caught and laundered into a null "discovery failed" result that callers read as an
        // IdP outage (and log at Error level).
        var handler = new RecordingHandler(_ => DiscoveryDocument());
        var sut = Build(handler);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sut.GetConfigurationAsync("https://idp.test", cts.Token));
    }

    [Fact]
    public async Task RefreshConfigurationAsync_FetchesFreshMetadata()
    {
        // After an IdP signing-key rollover, token validation forces a refresh and must get
        // freshly fetched metadata (and JWKS) back - not the stale cached snapshot that
        // ConfigurationManager would otherwise serve for up to ~12h.
        var handler = new RecordingHandler(_ => DiscoveryDocument(issuer: "https://idp.test"));
        var sut = Build(handler);
        const string discoveryUrl = "https://idp.test/.well-known/openid-configuration";

        await sut.GetConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);
        var fetchesAfterPrime = handler.RequestUris.Count(u => u == discoveryUrl);

        var refreshed = await sut.RefreshConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);

        Assert.NotNull(refreshed);
        Assert.Equal("https://idp.test", refreshed!.Issuer);
        Assert.True(handler.RequestUris.Count(u => u == discoveryUrl) > fetchesAfterPrime);
    }

    [Fact]
    public async Task RefreshConfigurationAsync_UnknownAuthority_ReturnsNull_NoHttpCall()
    {
        // No metadata has ever been loaded for the authority - nothing to refresh, and a
        // forced refresh must not become a way to make the service fetch arbitrary URLs.
        var handler = new RecordingHandler(_ => DiscoveryDocument());
        var sut = Build(handler);

        Assert.Null(await sut.RefreshConfigurationAsync("https://never-seen.test", TestContext.Current.CancellationToken));
        Assert.Null(await sut.RefreshConfigurationAsync(null!, TestContext.Current.CancellationToken));
        Assert.Null(await sut.RefreshConfigurationAsync("", TestContext.Current.CancellationToken));
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RefreshConfigurationAsync_ThrottledWithinMinInterval_AllowedAfterItElapses()
    {
        // The refresh trigger (unknown kid) is attacker-controllable on the unauthenticated
        // back-channel logout endpoint, so forced fetches are rate-limited per authority.
        var handler = new RecordingHandler(_ => DiscoveryDocument(issuer: "https://idp.test"));
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-06-10T12:00:00Z"));
        var sut = Build(handler, timeProvider: time);

        await sut.GetConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);
        var callsAfterPrime = handler.Calls;

        Assert.NotNull(await sut.RefreshConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken));
        var callsAfterRefresh = handler.Calls;

        // Second forced refresh inside the window: throttled, no HTTP traffic.
        Assert.Null(await sut.RefreshConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken));
        Assert.Equal(callsAfterRefresh, handler.Calls);

        // Once the interval elapses, a forced refresh works again. (Callers always load via
        // GetConfigurationAsync first - validation needs the cached config before it can fail
        // with key-not-found - which recreates the manager the successful refresh dropped.)
        time.Advance(DiscoveryService.ForcedRefreshMinInterval);
        await sut.GetConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);
        Assert.NotNull(await sut.RefreshConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken));
        Assert.True(handler.Calls > callsAfterRefresh);
        Assert.True(callsAfterRefresh > callsAfterPrime);
    }

    [Fact]
    public async Task RefreshConfigurationAsync_FetchFailure_ReturnsNull_KeepsCachedConfiguration()
    {
        // A failed forced refresh (IdP metadata endpoint down) must not throw and - critically -
        // must not evict the cached configuration that every other consumer depends on.
        var failing = false;
        var handler = new RecordingHandler(_ => failing
            ? new HttpResponseMessage(HttpStatusCode.InternalServerError)
            : DiscoveryDocument(issuer: "https://idp.test"));
        var sut = Build(handler);

        await sut.GetConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);
        failing = true;

        var refreshed = await sut.RefreshConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);
        var cached = await sut.GetConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);

        Assert.Null(refreshed);
        Assert.NotNull(cached);
        Assert.Equal("https://idp.test", cached!.Issuer);
    }

    [Fact]
    public async Task GetConfigurationAsync_ResolvesFreshClientFromFactoryPerFetch()
    {
        // Regression (L11): the per-authority ConfigurationManager lives for the process
        // lifetime. Pinning the HttpClient created when the manager was built would defeat
        // the factory's handler rotation (DNS refresh, connection recycling) for that
        // authority forever, so every document fetch must resolve a fresh client. Discovery
        // performs two fetches (metadata + JWKS); each must have asked the factory.
        var handler = new RecordingHandler(_ => DiscoveryDocument(issuer: "https://idp.test"));
        var factory = new CountingClientFactory(handler);
        var monitor = new StaticOptionsMonitor<SessionAuthenticationConfiguration>(
            new SessionAuthenticationConfiguration { RequireHttpsMetadata = false });
        var sut = new DiscoveryService(factory, monitor, NullLogger<DiscoveryService>.Instance);

        await sut.GetConfigurationAsync("https://idp.test", TestContext.Current.CancellationToken);

        Assert.True(handler.Calls >= 2, "discovery flow should fetch metadata and JWKS");
        Assert.Equal(handler.Calls, factory.CreateClientCalls);
    }

    [Fact]
    public async Task FactoryDocumentRetriever_ReadsRequireHttpsMetadataPerFetch()
    {
        // Regression (L11): RequireHttps used to be snapshotted into the manager's retriever
        // when the manager was first created, so flipping RequireHttpsMetadata via the options
        // monitor required a process restart to take effect.
        var handler = new RecordingHandler(_ => DiscoveryDocument(issuer: "http://idp.test"));
        var factory = new SingleClientFactory(new HttpClient(handler));
        var monitor = new MutableOptionsMonitor<SessionAuthenticationConfiguration>(
            new SessionAuthenticationConfiguration { RequireHttpsMetadata = true });
        var retriever = new DiscoveryService.FactoryDocumentRetriever(factory, monitor);
        const string metadataUrl = "http://idp.test/.well-known/openid-configuration";

        // RequireHttps=true: blocked before any HTTP traffic.
        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => retriever.GetDocumentAsync(metadataUrl, TestContext.Current.CancellationToken));
        Assert.Equal(0, handler.Calls);

        monitor.Value = new SessionAuthenticationConfiguration { RequireHttpsMetadata = false };

        var document = await retriever.GetDocumentAsync(metadataUrl, TestContext.Current.CancellationToken);
        Assert.Contains("http://idp.test", document);
        Assert.Equal(1, handler.Calls);
    }

    private static HttpResponseMessage DiscoveryDocument(string issuer = "https://idp.test")
    {
        var json = $$"""
        {
            "issuer": "{{issuer}}",
            "authorization_endpoint": "{{issuer}}/connect/authorize",
            "token_endpoint": "{{issuer}}/connect/token",
            "jwks_uri": "{{issuer}}/.well-known/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        }
        """;
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private static DiscoveryService Build(
        HttpMessageHandler handler,
        SessionAuthenticationConfiguration? config = null,
        TimeProvider? timeProvider = null)
    {
        var factory = new SingleClientFactory(new HttpClient(handler));
        var monitor = new StaticOptionsMonitor<SessionAuthenticationConfiguration>(
            config ?? new SessionAuthenticationConfiguration { RequireHttpsMetadata = false });
        return new DiscoveryService(factory, monitor, NullLogger<DiscoveryService>.Instance, timeProvider);
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public List<string> RequestUris { get; } = new();
        public int Calls => RequestUris.Count;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            RequestUris.Add(request.RequestUri!.ToString());
            return Task.FromResult(respond(request));
        }
    }

    private sealed class SingleClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class CountingClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public int CreateClientCalls { get; private set; }

        public HttpClient CreateClient(string name)
        {
            CreateClientCalls++;
            return new HttpClient(handler, disposeHandler: false);
        }
    }

    private sealed class StaticOptionsMonitor<T>(T value) : Microsoft.Extensions.Options.IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class MutableOptionsMonitor<T>(T value) : Microsoft.Extensions.Options.IOptionsMonitor<T>
    {
        public T Value { get; set; } = value;
        public T CurrentValue => Value;
        public T Get(string? name) => Value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }
}
