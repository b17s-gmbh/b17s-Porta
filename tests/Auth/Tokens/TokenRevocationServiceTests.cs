using System.Net;
using System.Net.Http.Headers;
using System.Text;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Tests.Fixtures;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace b17s.Porta.Tests.Auth.Tokens;

public sealed class TokenRevocationServiceTests
{
    [Fact]
    public async Task RevokeTokenAsync_EmptyToken_ReturnsFalse_NoHttpCall()
    {
        // Empty token is a no-op - the IdP would reject it anyway and we don't want to
        // ferry the resulting 4xx through logs/telemetry as a failure.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sut = BuildWithOptions(handler);

        var result = await sut.RevokeTokenAsync(
            "",
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RevokeTokenAsync_MissingRevocationEndpoint_ReturnsFalse_NoHttpCall()
    {
        // Endpoint not configured -> fail closed. Posting to "" would NRE inside HttpClient.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sut = BuildWithOptions(handler);

        var result = await sut.RevokeTokenAsync(
            "tok",
            new TokenRevocationOptions
            {
                RevocationEndpoint = "",
                ClientId = "c",
                ClientSecret = "s",
            },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RevokeTokenAsync_SuccessfulResponse_ReturnsTrue()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sut = BuildWithOptions(handler);

        var result = await sut.RevokeTokenAsync(
            "tok",
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result);
        Assert.Equal(1, handler.Calls);
        Assert.Equal("https://idp.test/revoke", handler.LastRequest!.RequestUri!.ToString());
        Assert.Equal(HttpMethod.Post, handler.LastRequest.Method);
    }

    [Fact]
    public async Task RevokeTokenAsync_SendsTokenAndOptionalTokenTypeHint_InFormBody()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sut = BuildWithOptions(handler);

        await sut.RevokeTokenAsync(
            "the-token",
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            tokenTypeHint: "refresh_token",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("the-token", handler.LastForm!["token"]);
        Assert.Equal("refresh_token", handler.LastForm["token_type_hint"]);
    }

    [Fact]
    public async Task RevokeTokenAsync_OmitsTokenTypeHint_WhenNotSupplied()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sut = BuildWithOptions(handler);

        await sut.RevokeTokenAsync(
            "tok",
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(handler.LastForm!.ContainsKey("token_type_hint"));
    }

    [Fact]
    public async Task RevokeTokenAsync_UsesBasicAuth_WithPercentEncodedCredentials()
    {
        // RFC 6749 §2.3.1: client_id and client_secret must be percent-encoded *before*
        // forming the userid:password pair. A literal ':' or space in the secret would
        // otherwise corrupt the credential and the IdP would reject the request.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sut = BuildWithOptions(handler);

        await sut.RevokeTokenAsync(
            "tok",
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "client id",
                ClientSecret = "secret:with:colons",
            },
            cancellationToken: TestContext.Current.CancellationToken);

        var auth = handler.LastRequest!.Headers.Authorization;
        Assert.NotNull(auth);
        Assert.Equal("Basic", auth!.Scheme);
        var raw = Encoding.UTF8.GetString(Convert.FromBase64String(auth.Parameter!));
        Assert.Equal("client%20id:secret%3Awith%3Acolons", raw);
    }

    [Fact]
    public async Task RevokeTokenAsync_NonSuccessResponse_ReturnsFalse()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("""{"error":"unsupported_token_type"}"""),
        });
        var sut = BuildWithOptions(handler);

        var result = await sut.RevokeTokenAsync(
            "tok",
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result);
    }

    [Fact]
    public async Task RevokeTokenAsync_NetworkException_ReturnsFalse()
    {
        // Service must swallow transport exceptions - the caller is typically the
        // logout pipeline, which should still complete even if the IdP is unreachable.
        var handler = new ThrowingHandler(new HttpRequestException("network down"));
        var sut = BuildWithOptions(handler);

        var result = await sut.RevokeTokenAsync(
            "tok",
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result);
    }

    [Fact]
    public async Task RevokeTokenAsync_OidcOverload_AuthorityMissing_ReturnsFalse_NoHttpCall()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var config = new SessionAuthenticationConfiguration { Authority = "" };
        var sut = Build(handler, config, discovery: null);

        var result = await sut.RevokeTokenAsync("tok", cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RevokeTokenAsync_OidcOverload_DiscoveryHasNoRevocationEndpoint_ReturnsFalse_NoHttpCall()
    {
        // If the IdP doesn't advertise revocation_endpoint we can't guess the URL.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var config = new SessionAuthenticationConfiguration
        {
            Authority = "https://idp.test",
            ClientId = "c",
            ClientSecret = "s",
        };
        var sut = Build(handler, config, discovery: new OpenIdConnectConfiguration());

        var result = await sut.RevokeTokenAsync("tok", cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RevokeTokenAsync_OidcOverload_ClientCredentialsMissing_ReturnsFalse_NoHttpCall()
    {
        // Half-credentials must not leak as a Basic header with an empty field.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var config = new SessionAuthenticationConfiguration
        {
            Authority = "https://idp.test",
            ClientId = "c",
            ClientSecret = "", // intentionally absent
        };
        var sut = Build(handler, config, WithRevocationEndpoint());

        var result = await sut.RevokeTokenAsync("tok", cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RevokeTokenAsync_OidcOverload_DelegatesToConfiguredEndpoint()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var config = new SessionAuthenticationConfiguration
        {
            Authority = "https://idp.test",
            ClientId = "c",
            ClientSecret = "s",
        };
        var sut = Build(handler, config, WithRevocationEndpoint());

        var result = await sut.RevokeTokenAsync("tok", "access_token", TestContext.Current.CancellationToken);

        Assert.True(result);
        Assert.Equal("https://idp.test/connect/revoke", handler.LastRequest!.RequestUri!.ToString());
        Assert.Equal("access_token", handler.LastForm!["token_type_hint"]);
    }

    [Fact]
    public async Task RevokeTokensAsync_EmptyArray_ReturnsAllRevoked_NoHttpCall()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sut = BuildWithOptions(handler);

        var result = await sut.RevokeTokensAsync(
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            TestContext.Current.CancellationToken);

        Assert.True(result.AllRevoked);
        Assert.True(result.RefreshTokensRevoked);
        Assert.Empty(result.Outcomes);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RevokeTokensAsync_AllSucceed_ReturnsAllRevoked()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sut = BuildWithOptions(handler);

        var result = await sut.RevokeTokensAsync(
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            TestContext.Current.CancellationToken,
            ("access-tok", "access_token"),
            ("refresh-tok", "refresh_token"));

        Assert.True(result.AllRevoked);
        Assert.True(result.RefreshTokensRevoked);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task RevokeTokensAsync_PartialFailure_ReportsPerTokenOutcome_StillRevokesRemaining()
    {
        // W5: a single bool hid which token survived. The batch result now reports each
        // outcome, and refresh tokens are revoked first so the dangerous one is dealt with
        // even if a later revocation fails. Here the (first-attempted) refresh token gets
        // the OK response and the access token gets the failure.
        var responses = new Queue<HttpResponseMessage>(new[]
        {
            new HttpResponseMessage(HttpStatusCode.OK),
            new HttpResponseMessage(HttpStatusCode.BadRequest),
        });
        var handler = new RecordingHandler(_ => responses.Dequeue());
        var sut = BuildWithOptions(handler);

        var result = await sut.RevokeTokensAsync(
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            TestContext.Current.CancellationToken,
            ("access-tok", "access_token"),
            ("refresh-tok", "refresh_token"));

        Assert.False(result.AllRevoked);
        Assert.True(result.RefreshTokensRevoked); // refresh attempted first → got the OK response
        Assert.Equal(2, handler.Calls); // access-token revocation still attempted
        Assert.Equal("refresh_token", result.Outcomes[0].TokenTypeHint); // prioritized first
        Assert.True(result.Outcomes[0].Revoked);
        Assert.False(result.Outcomes[1].Revoked);
    }

    [Fact]
    public async Task RevokeTokensAsync_RefreshTokenFails_RefreshTokensRevokedIsFalse()
    {
        // The refresh token (attempted first) fails while the access token succeeds.
        var responses = new Queue<HttpResponseMessage>(new[]
        {
            new HttpResponseMessage(HttpStatusCode.BadRequest),
            new HttpResponseMessage(HttpStatusCode.OK),
        });
        var handler = new RecordingHandler(_ => responses.Dequeue());
        var sut = BuildWithOptions(handler);

        var result = await sut.RevokeTokensAsync(
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            TestContext.Current.CancellationToken,
            ("access-tok", "access_token"),
            ("refresh-tok", "refresh_token"));

        Assert.False(result.AllRevoked);
        Assert.False(result.RefreshTokensRevoked); // the dangerous token is still live
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task RevokeTokensAsync_OidcOverload_DelegatesPerTokenViaDiscovery()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var config = new SessionAuthenticationConfiguration
        {
            Authority = "https://idp.test",
            ClientId = "c",
            ClientSecret = "s",
        };
        var sut = Build(handler, config, WithRevocationEndpoint());

        var result = await sut.RevokeTokensAsync(
            TestContext.Current.CancellationToken,
            ("a", "access_token"),
            ("b", "refresh_token"));

        Assert.True(result.AllRevoked);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task RevokeTokenAsync_Cancellation_Propagates_NotSwallowedAsFalse()
    {
        // Caller cancellation (client disconnect / request timeout / host shutdown) must surface as
        // cancellation rather than be caught and collapsed to a "revocation failed" false.
        var handler = new ThrowingHandler(new OperationCanceledException());
        var sut = BuildWithOptions(handler);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sut.RevokeTokenAsync(
            "tok",
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            cancellationToken: cts.Token));
    }

    [Fact]
    public async Task RevokeTokensAsync_Cancellation_AbortsBatch_DoesNotAttemptRemainingTokens()
    {
        // Cancellation mid-batch must abort the loop. Previously each per-token revocation swallowed
        // the cancellation (returning false), so the foreach kept iterating and wasted a doomed
        // round-trip on every remaining token. The first attempt should throw and stop the batch.
        var handler = new RecordingHandler(_ => throw new OperationCanceledException());
        var sut = BuildWithOptions(handler);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sut.RevokeTokensAsync(
            new TokenRevocationOptions
            {
                RevocationEndpoint = "https://idp.test/revoke",
                ClientId = "c",
                ClientSecret = "s",
            },
            cts.Token,
            ("refresh-tok", "refresh_token"),
            ("access-tok", "access_token")));

        Assert.Equal(1, handler.Calls);
    }

    private static OpenIdConnectConfiguration WithRevocationEndpoint() =>
        new() { AdditionalData = { ["revocation_endpoint"] = "https://idp.test/connect/revoke" } };

    private static TokenRevocationService BuildWithOptions(HttpMessageHandler handler) =>
        Build(handler, new SessionAuthenticationConfiguration(), discovery: null);

    private static TokenRevocationService Build(
        HttpMessageHandler handler,
        SessionAuthenticationConfiguration config,
        OpenIdConnectConfiguration? discovery)
    {
        var factory = new SingleClientFactory(new HttpClient(handler));
        var discoveryService = new StaticDiscoveryService(discovery);
        var core = new StaticOptionsMonitor<PortaCoreOptions>(new PortaCoreOptions());
        return new TokenRevocationService(
            factory,
            discoveryService,
            Options.Create(config),
            core,
            NullLogger<TokenRevocationService>.Instance);
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public Dictionary<string, string>? LastForm { get; private set; }
        public int Calls { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            LastRequest = request;
            if (request.Content is FormUrlEncodedContent)
            {
                var body = await request.Content.ReadAsStringAsync(cancellationToken);
                LastForm = body.Split('&', StringSplitOptions.RemoveEmptyEntries)
                    .Select(kv => kv.Split('=', 2))
                    .ToDictionary(parts => Uri.UnescapeDataString(parts[0]), parts => Uri.UnescapeDataString(parts[1]));
            }
            return respond(request);
        }
    }

    private sealed class ThrowingHandler(Exception ex) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => throw ex;
    }

    private sealed class SingleClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class StaticDiscoveryService(OpenIdConnectConfiguration? config) : IDiscoveryService
    {
        public Task<OpenIdConnectConfiguration?> GetConfigurationAsync(string authority, CancellationToken cancellationToken = default)
            => Task.FromResult(config);

        public Task<OpenIdConnectConfiguration?> RefreshConfigurationAsync(string authority, CancellationToken cancellationToken = default)
            => Task.FromResult<OpenIdConnectConfiguration?>(null);
    }
}
