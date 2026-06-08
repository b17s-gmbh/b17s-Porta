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

    private static DiscoveryService Build(HttpMessageHandler handler, SessionAuthenticationConfiguration? config = null)
    {
        var factory = new SingleClientFactory(new HttpClient(handler));
        var monitor = new StaticOptionsMonitor<SessionAuthenticationConfiguration>(
            config ?? new SessionAuthenticationConfiguration { RequireHttpsMetadata = false });
        return new DiscoveryService(factory, monitor, NullLogger<DiscoveryService>.Instance);
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

    private sealed class StaticOptionsMonitor<T>(T value) : Microsoft.Extensions.Options.IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
