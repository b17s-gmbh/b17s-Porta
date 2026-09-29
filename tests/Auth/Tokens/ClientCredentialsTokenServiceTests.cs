using System.Net;
using System.Text;
using System.Text.Json;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Tests.Fixtures;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace b17s.Porta.Tests.Auth.Tokens;

/// <summary>
/// Unit tests for <see cref="ClientCredentialsTokenService"/>: the process-wide token cache
/// behind the ClientCredentials backend-auth policy. The cache semantics are the point of the
/// service - a broken expiry or a cached failure silently multiplies IdP traffic or poisons
/// every backend call - so each branch is pinned here against a counting fake token endpoint.
/// </summary>
public sealed class ClientCredentialsTokenServiceTests
{
    private static ClientCredentialsTokenRequest Request(
        string? scope = null,
        string? audience = null,
        string clientSecret = "s3cret") => new()
        {
            TokenEndpoint = "https://idp.test/connect/token",
            ClientId = "bff-m2m",
            ClientSecret = clientSecret,
            Scope = scope,
            Audience = audience,
        };

    private static ClientCredentialsTokenService Service(FakeTokenEndpoint endpoint, FakeTimeProvider time) =>
        new(
            new FakeHttpClientFactory(endpoint),
            new FakeOptionsMonitor(new PortaCoreOptions()),
            time,
            NullLogger<ClientCredentialsTokenService>.Instance);

    [Fact]
    public async Task FirstCall_PostsClientCredentialsForm_WithScopeAndAudience()
    {
        var endpoint = new FakeTokenEndpoint();
        var service = Service(endpoint, new FakeTimeProvider());

        var token = await service.GetTokenAsync(
            Request(scope: "orders.read", audience: "orders-api"),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("token-1", token);
        var form = Assert.Single(endpoint.ReceivedForms);
        Assert.Equal("client_credentials", form["grant_type"]);
        Assert.Equal("bff-m2m", form["client_id"]);
        Assert.Equal("s3cret", form["client_secret"]);
        Assert.Equal("orders.read", form["scope"]);
        Assert.Equal("orders-api", form["audience"]);
    }

    [Fact]
    public async Task PrivateKeyJwt_SendsClientAssertion_InsteadOfSecret()
    {
        // Entra ID certificate credential: client_id + signed assertion, aud = token endpoint,
        // certificate thumbprint in the header, and no secret on the wire.
        using var key = TestSigningKey.Rsa();
        var endpoint = new FakeTokenEndpoint();
        var time = new FakeTimeProvider();
        var service = Service(endpoint, time);

        await service.GetTokenAsync(
            Request(clientSecret: "") with { PrivateKeyJwt = new PrivateKeyJwtOptions { Key = key.PemWithCertificate } },
            cancellationToken: TestContext.Current.CancellationToken);

        var form = Assert.Single(endpoint.ReceivedForms);
        Assert.Equal("bff-m2m", form["client_id"]);
        Assert.False(form.ContainsKey("client_secret"));
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form["client_assertion_type"]);

        var jwt = new JsonWebToken(form["client_assertion"]);
        Assert.Equal("bff-m2m", jwt.Issuer);
        Assert.Equal(["https://idp.test/connect/token"], jwt.Audiences);
        Assert.Equal(key.X5t, jwt.GetHeaderValue<string>("x5t"));
        // Assertion times come from the injected TimeProvider.
        Assert.Equal(time.GetUtcNow().ToUnixTimeSeconds(), new DateTimeOffset(jwt.IssuedAt).ToUnixTimeSeconds());
    }

    [Fact]
    public async Task PrivateKeyJwt_AudienceOverride_IsUsed()
    {
        using var key = TestSigningKey.Rsa();
        var endpoint = new FakeTokenEndpoint();
        var service = Service(endpoint, new FakeTimeProvider());

        await service.GetTokenAsync(
            Request() with { PrivateKeyJwt = new PrivateKeyJwtOptions { Key = key.Pkcs8Pem, Audience = "https://idp.test" } },
            cancellationToken: TestContext.Current.CancellationToken);

        var jwt = new JsonWebToken(Assert.Single(endpoint.ReceivedForms)["client_assertion"]);
        Assert.Equal(["https://idp.test"], jwt.Audiences);
    }

    [Fact]
    public async Task PrivateKeyJwt_DifferentKeys_DoNotShareCachedToken()
    {
        // The credential is part of the cache identity, so rotating the key mints a fresh token.
        using var keyA = TestSigningKey.Rsa();
        using var keyB = TestSigningKey.Rsa();
        var endpoint = new FakeTokenEndpoint(expiresIn: 3600);
        var service = Service(endpoint, new FakeTimeProvider());

        var first = await service.GetTokenAsync(
            Request() with { PrivateKeyJwt = new PrivateKeyJwtOptions { Key = keyA.Pkcs8Pem } },
            cancellationToken: TestContext.Current.CancellationToken);
        var second = await service.GetTokenAsync(
            Request() with { PrivateKeyJwt = new PrivateKeyJwtOptions { Key = keyB.Pkcs8Pem } },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotEqual(first, second);
        Assert.Equal(2, endpoint.ReceivedForms.Count);
    }

    [Fact]
    public async Task PrivateKeyJwt_UnloadableKey_ThrowsConfigurationException_WithoutCallingIdp()
    {
        // A distinct type, so callers can tell misconfiguration from a token-endpoint rejection.
        var endpoint = new FakeTokenEndpoint();
        var service = Service(endpoint, new FakeTimeProvider());

        var ex = await Assert.ThrowsAsync<ClientCredentialsConfigurationException>(() => service.GetTokenAsync(
            Request() with { PrivateKeyJwt = new PrivateKeyJwtOptions { Key = "not a key" } },
            cancellationToken: TestContext.Current.CancellationToken));

        Assert.StartsWith("PrivateKeyJwt is invalid", ex.Message);
        Assert.Empty(endpoint.ReceivedForms);
    }

    [Fact]
    public async Task PrivateKeyJwt_ZitadelKeyFile_EmptyClientId_ResolvesClientIdFromKeyFile()
    {
        // Direct callers of the public service (not just the built-in handler) get the Zitadel
        // key file's client id in both the form and the assertion's iss/sub.
        using var key = TestSigningKey.Rsa();
        var endpoint = new FakeTokenEndpoint();
        var service = Service(endpoint, new FakeTimeProvider());

        await service.GetTokenAsync(
            Request(clientSecret: "") with
            {
                ClientId = "",
                PrivateKeyJwt = new PrivateKeyJwtOptions { Key = key.ZitadelKeyFile(clientId: "app@project") },
            },
            cancellationToken: TestContext.Current.CancellationToken);

        var form = Assert.Single(endpoint.ReceivedForms);
        Assert.Equal("app@project", form["client_id"]);
        // Parsed rather than validated: assertion times come from the fake clock, which is in the past.
        var jwt = new JsonWebToken(form["client_assertion"]);
        Assert.Equal("app@project", jwt.Issuer);
        Assert.Equal("app@project", jwt.Subject);
    }

    [Theory]
    [InlineData("zitadel", "other-client", "does not match")]
    [InlineData("pem", "", "ClientId is required")]
    public async Task PrivateKeyJwt_UnresolvableClientId_ThrowsConfigurationException(string keyKind, string clientId, string expected)
    {
        using var key = TestSigningKey.Rsa();
        var endpoint = new FakeTokenEndpoint();
        var service = Service(endpoint, new FakeTimeProvider());
        var keyMaterial = keyKind == "zitadel" ? key.ZitadelKeyFile(clientId: "app@project") : key.Pkcs8Pem;

        var ex = await Assert.ThrowsAsync<ClientCredentialsConfigurationException>(() => service.GetTokenAsync(
            Request(clientSecret: "") with { ClientId = clientId, PrivateKeyJwt = new PrivateKeyJwtOptions { Key = keyMaterial } },
            cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains(expected, ex.Message);
        Assert.Empty(endpoint.ReceivedForms);
    }

    [Fact]
    public async Task PrivateKeyJwt_KeyFailure_IsNotCached_FixedKeyWorksOnNextCall()
    {
        using var key = TestSigningKey.Rsa();
        var endpoint = new FakeTokenEndpoint();
        var service = Service(endpoint, new FakeTimeProvider());
        var path = Path.Combine(Path.GetTempPath(), $"porta-cc-key-{Guid.NewGuid():N}.pem");
        var request = Request(clientSecret: "") with { PrivateKeyJwt = new PrivateKeyJwtOptions { KeyFile = path } };

        try
        {
            await Assert.ThrowsAsync<ClientCredentialsConfigurationException>(
                () => service.GetTokenAsync(request, cancellationToken: TestContext.Current.CancellationToken));

            File.WriteAllText(path, key.Pkcs8Pem);
            var token = await service.GetTokenAsync(request, cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal("token-1", token);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task OptionalFields_AreOmitted_WhenUnset()
    {
        // Some IdPs reject empty scope/audience values, so absent config must mean absent field.
        var endpoint = new FakeTokenEndpoint();
        var service = Service(endpoint, new FakeTimeProvider());

        await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);

        var form = Assert.Single(endpoint.ReceivedForms);
        Assert.False(form.ContainsKey("scope"));
        Assert.False(form.ContainsKey("audience"));
    }

    [Fact]
    public async Task SecondCall_IsServedFromCache()
    {
        var endpoint = new FakeTokenEndpoint(expiresIn: 3600);
        var service = Service(endpoint, new FakeTimeProvider());

        var first = await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);
        var second = await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(first, second);
        Assert.Equal(1, endpoint.CallCount);
    }

    [Fact]
    public async Task ExpiredToken_IsRefetched()
    {
        var time = new FakeTimeProvider();
        var endpoint = new FakeTokenEndpoint(expiresIn: 3600);
        var service = Service(endpoint, time);

        var first = await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);
        // Advance past expiry minus the 60s safety margin.
        time.Advance(TimeSpan.FromSeconds(3600 - 30));
        var second = await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("token-1", first);
        Assert.Equal("token-2", second);
        Assert.Equal(2, endpoint.CallCount);
    }

    [Fact]
    public async Task TokenIsRefreshed_WithinSafetyMargin_BeforeActualExpiry()
    {
        // A token must never be served in its final 60 seconds - in-flight backend calls would
        // race the expiry.
        var time = new FakeTimeProvider();
        var endpoint = new FakeTokenEndpoint(expiresIn: 3600);
        var service = Service(endpoint, time);

        await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);
        time.Advance(TimeSpan.FromSeconds(3600 - 59)); // inside the margin, before real expiry
        await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(2, endpoint.CallCount);
    }

    [Fact]
    public async Task FailedAcquisition_IsNotCached_NextCallRetries()
    {
        var endpoint = new FakeTokenEndpoint { FailuresBeforeSuccess = 1 };
        var service = Service(endpoint, new FakeTimeProvider());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken));
        var token = await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("token-2", token);
        Assert.Equal(2, endpoint.CallCount);
    }

    [Fact]
    public async Task EmptyAccessToken_Throws_FailClosed()
    {
        // "Authorization: Bearer " (empty) reads as anonymous to many backends - never forward it.
        var endpoint = new FakeTokenEndpoint { ReturnEmptyToken = true };
        var service = Service(endpoint, new FakeTimeProvider());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DifferentScopes_GetSeparateCacheEntries()
    {
        var endpoint = new FakeTokenEndpoint();
        var service = Service(endpoint, new FakeTimeProvider());

        await service.GetTokenAsync(Request(scope: "orders.read"), cancellationToken: TestContext.Current.CancellationToken);
        await service.GetTokenAsync(Request(scope: "users.read"), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(2, endpoint.CallCount);
    }

    [Fact]
    public async Task RotatedSecret_MintsFreshToken_InsteadOfServingStaleOne()
    {
        // The cache key includes a hash of the secret: after a rotation the old entry must not
        // keep serving a token issued to the previous credential.
        var endpoint = new FakeTokenEndpoint(expiresIn: 3600);
        var service = Service(endpoint, new FakeTimeProvider());

        await service.GetTokenAsync(Request(clientSecret: "old"), cancellationToken: TestContext.Current.CancellationToken);
        await service.GetTokenAsync(Request(clientSecret: "new"), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(2, endpoint.CallCount);
    }

    [Fact]
    public async Task ZeroExpiresIn_DisablesCaching_ForThatToken()
    {
        // A token whose lifetime the IdP didn't state cannot be safely cached.
        var endpoint = new FakeTokenEndpoint(expiresIn: 0);
        var service = Service(endpoint, new FakeTimeProvider());

        await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);
        await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(2, endpoint.CallCount);
    }

    [Fact]
    public async Task ForceRefresh_EvictsCachedToken_AndMintsFresh()
    {
        // The 401-retry path: the cached token was rejected by the backend, so forceRefresh must
        // discard it and mint - and the fresh token must then serve subsequent normal calls.
        var endpoint = new FakeTokenEndpoint(expiresIn: 3600);
        var service = Service(endpoint, new FakeTimeProvider());

        var first = await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);
        var second = await service.GetTokenAsync(Request(), forceRefresh: true, cancellationToken: TestContext.Current.CancellationToken);
        var third = await service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("token-1", first);
        Assert.Equal("token-2", second);
        Assert.Equal("token-2", third);
        Assert.Equal(2, endpoint.CallCount);
    }

    [Fact]
    public async Task ConcurrentCallers_ShareOneInFlightFetch()
    {
        var endpoint = new FakeTokenEndpoint(expiresIn: 3600) { Delay = TimeSpan.FromMilliseconds(50) };
        var service = Service(endpoint, new FakeTimeProvider());

        var tokens = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            service.GetTokenAsync(Request(), cancellationToken: TestContext.Current.CancellationToken)));

        Assert.All(tokens, t => Assert.Equal("token-1", t));
        Assert.Equal(1, endpoint.CallCount);
    }

    // -- fakes ---------------------------------------------------------------------------------

    private sealed class FakeTokenEndpoint(int expiresIn = 3600) : HttpMessageHandler
    {
        private int _calls;

        public int CallCount => _calls;
        public int FailuresBeforeSuccess { get; init; }
        public bool ReturnEmptyToken { get; init; }
        public TimeSpan Delay { get; set; }
        public List<Dictionary<string, string>> ReceivedForms { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Delay > TimeSpan.Zero)
            {
                await Task.Delay(Delay, cancellationToken);
            }

            var call = Interlocked.Increment(ref _calls);

            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            var form = body.Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(pair => pair.Split('=', 2))
                .ToDictionary(kv => Uri.UnescapeDataString(kv[0]), kv => Uri.UnescapeDataString(kv[1]));
            lock (ReceivedForms)
            {
                ReceivedForms.Add(form);
            }

            if (call <= FailuresBeforeSuccess)
            {
                return new HttpResponseMessage(HttpStatusCode.InternalServerError);
            }

            var token = ReturnEmptyToken ? "" : $"token-{call}";
            var json = JsonSerializer.Serialize(new { access_token = token, token_type = "Bearer", expires_in = expiresIn });
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class FakeHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class FakeOptionsMonitor(PortaCoreOptions value) : IOptionsMonitor<PortaCoreOptions>
    {
        public PortaCoreOptions CurrentValue => value;
        public PortaCoreOptions Get(string? name) => value;
        public IDisposable? OnChange(Action<PortaCoreOptions, string?> listener) => null;
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.Parse("2026-08-12T12:00:00Z");
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }
}
