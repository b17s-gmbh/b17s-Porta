using System.Net;
using System.Net.Http.Json;
using System.Text;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace b17s.Porta.Tests.Auth.Tokens;

/// <summary>
/// Behavioural tests for <see cref="TokenRefreshService"/> - both the provider-agnostic
/// options overload and the OIDC-discovery overload. Covers the guard clauses (which must
/// short-circuit before any HTTP call), the RFC 6749 refresh form body, and the
/// success / failure / null-body / network-exception outcomes.
/// </summary>
public sealed class TokenRefreshServiceTests
{
    private static readonly TokenRefreshOptions ValidOptions = new()
    {
        TokenEndpoint = "https://idp.test/token",
        ClientId = "bff-client",
        ClientSecret = "bff-secret",
        Scope = null,
    };

    [Fact]
    public async Task RefreshAsync_Options_EmptyRefreshToken_ReturnsNull_NoHttpCall()
    {
        var handler = new RecordingHandler(_ => OkRefresh());
        var sut = Build(handler);

        var result = await sut.RefreshAsync("", ValidOptions, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RefreshAsync_Options_EmptyTokenEndpoint_ReturnsNull_NoHttpCall()
    {
        // An empty endpoint would NRE / hit a bad URL inside HttpClient; fail closed first.
        var handler = new RecordingHandler(_ => OkRefresh());
        var sut = Build(handler);

        var result = await sut.RefreshAsync(
            "refresh-123",
            new TokenRefreshOptions { TokenEndpoint = "", ClientId = "c", ClientSecret = "s" },
            TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RefreshAsync_Options_BuildsRfc6749RefreshForm()
    {
        var handler = new RecordingHandler(_ => OkRefresh());
        var sut = Build(handler);

        await sut.RefreshAsync("refresh-123", ValidOptions, TestContext.Current.CancellationToken);

        Assert.Equal("https://idp.test/token", handler.LastRequest!.RequestUri!.ToString());
        Assert.Equal(HttpMethod.Post, handler.LastRequest.Method);
        Assert.Equal("refresh_token", handler.LastForm!["grant_type"]);
        Assert.Equal("refresh-123", handler.LastForm["refresh_token"]);
        Assert.Equal("bff-client", handler.LastForm["client_id"]);
        Assert.Equal("bff-secret", handler.LastForm["client_secret"]);
    }

    [Fact]
    public async Task RefreshAsync_Options_NoScope_OmitsScopeFromForm()
    {
        var handler = new RecordingHandler(_ => OkRefresh());
        var sut = Build(handler);

        await sut.RefreshAsync("refresh-123", ValidOptions, TestContext.Current.CancellationToken);

        Assert.DoesNotContain("scope", handler.LastForm!.Keys);
    }

    [Fact]
    public async Task RefreshAsync_Options_WithScope_IncludesScopeInForm()
    {
        var handler = new RecordingHandler(_ => OkRefresh());
        var sut = Build(handler);

        await sut.RefreshAsync(
            "refresh-123",
            new TokenRefreshOptions
            {
                TokenEndpoint = "https://idp.test/token",
                ClientId = "bff-client",
                ClientSecret = "bff-secret",
                Scope = "offline_access",
            },
            TestContext.Current.CancellationToken);

        Assert.Equal("offline_access", handler.LastForm!["scope"]);
    }

    [Fact]
    public async Task RefreshAsync_Options_SuccessfulResponse_DeserializesTokens()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = "new-refresh",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            }),
        });
        var sut = Build(handler);

        var result = await sut.RefreshAsync("refresh-123", ValidOptions, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal("new-access", result.Response!.AccessToken);
        Assert.Equal("new-refresh", result.Response.RefreshToken);
        Assert.Equal(3600, result.Response.ExpiresIn);
    }

    [Fact]
    public async Task RefreshAsync_Options_InvalidGrant_ClassifiesAsInvalidGrant()
    {
        // IdP rejects the refresh token itself (revoked/expired/rotated-out). The body may echo
        // the submitted refresh token back; the service must NOT leak it, but it must classify the
        // standard `invalid_grant` error code so the caller can force a sign-out (W3).
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("""{"error":"invalid_grant","refresh_token":"leaked-secret"}""",
                Encoding.UTF8, "application/json"),
        });
        var sut = Build(handler);

        var result = await sut.RefreshAsync("refresh-123", ValidOptions, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.True(result.IsInvalidGrant);
        Assert.Equal(RefreshFailureReason.InvalidGrant, result.Reason);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task RefreshAsync_Options_ServerError_ClassifiesAsTransient()
    {
        // A 5xx (or any non-invalid_grant failure) is transient: the refresh token may still be
        // valid, so the caller should keep the session and retry - NOT sign the user out.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
        {
            Content = new StringContent("upstream down", Encoding.UTF8, "text/plain"),
        });
        var sut = Build(handler);

        var result = await sut.RefreshAsync("refresh-123", ValidOptions, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.False(result.IsInvalidGrant);
        Assert.Equal(RefreshFailureReason.Transient, result.Reason);
    }

    [Fact]
    public async Task RefreshAsync_Options_NullDeserializedBody_ReturnsNull()
    {
        // 200 OK but the body deserializes to null - must not be treated as a successful refresh.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("null", Encoding.UTF8, "application/json"),
        });
        var sut = Build(handler);

        var result = await sut.RefreshAsync("refresh-123", ValidOptions, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task RefreshAsync_Options_HttpException_ReturnsNull()
    {
        var handler = new ThrowingHandler(new HttpRequestException("connect failed"));
        var sut = Build(handler);

        var result = await sut.RefreshAsync("refresh-123", ValidOptions, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public async Task RefreshAsync_Oidc_EmptyRefreshToken_ReturnsNull_NoDiscovery()
    {
        var handler = new RecordingHandler(_ => OkRefresh());
        var discovery = new StubDiscoveryService(OidcConfig("https://idp.test/token"));
        var sut = Build(handler, discovery: discovery, config: ValidConfig());

        var result = await sut.RefreshAsync("", TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(0, discovery.Calls);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RefreshAsync_Oidc_MissingConfiguration_ReturnsNull_NoDiscovery()
    {
        // Authority/ClientId/ClientSecret not configured -> fail closed before discovery.
        var handler = new RecordingHandler(_ => OkRefresh());
        var discovery = new StubDiscoveryService(OidcConfig("https://idp.test/token"));
        var sut = Build(handler, discovery: discovery, config: new SessionAuthenticationConfiguration());

        var result = await sut.RefreshAsync("refresh-123", TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(0, discovery.Calls);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RefreshAsync_Oidc_DiscoveryReturnsNull_ReturnsNull_NoHttpCall()
    {
        var handler = new RecordingHandler(_ => OkRefresh());
        var discovery = new StubDiscoveryService(null);
        var sut = Build(handler, discovery: discovery, config: ValidConfig());

        var result = await sut.RefreshAsync("refresh-123", TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(1, discovery.Calls);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RefreshAsync_Oidc_DiscoveryHasNoTokenEndpoint_ReturnsNull_NoHttpCall()
    {
        var handler = new RecordingHandler(_ => OkRefresh());
        var discovery = new StubDiscoveryService(OidcConfig(tokenEndpoint: null));
        var sut = Build(handler, discovery: discovery, config: ValidConfig());

        var result = await sut.RefreshAsync("refresh-123", TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task RefreshAsync_Oidc_HappyPath_UsesDiscoveredEndpointAndConfigCredentials()
    {
        var handler = new RecordingHandler(_ => OkRefresh());
        var discovery = new StubDiscoveryService(OidcConfig("https://discovered.test/token"));
        var sut = Build(handler, discovery: discovery, config: ValidConfig());

        var result = await sut.RefreshAsync("refresh-123", TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, discovery.Calls);
        Assert.Equal("https://discovered.test/token", handler.LastRequest!.RequestUri!.ToString());
        Assert.Equal("refresh_token", handler.LastForm!["grant_type"]);
        Assert.Equal("cfg-client", handler.LastForm["client_id"]);
        Assert.Equal("cfg-secret", handler.LastForm["client_secret"]);
    }

    private static SessionAuthenticationConfiguration ValidConfig() => new()
    {
        Authority = "https://idp.test",
        ClientId = "cfg-client",
        ClientSecret = "cfg-secret",
        Scope = "openid",
    };

    private static OpenIdConnectConfiguration OidcConfig(string? tokenEndpoint)
        => new() { TokenEndpoint = tokenEndpoint };

    private static HttpResponseMessage OkRefresh() => new(HttpStatusCode.OK)
    {
        Content = JsonContent.Create(new TokenExchangeResponse
        {
            AccessToken = "new-access",
            ExpiresIn = 600,
            TokenType = "Bearer",
        }),
    };

    private static TokenRefreshService Build(
        HttpMessageHandler handler,
        IDiscoveryService? discovery = null,
        SessionAuthenticationConfiguration? config = null,
        PortaCoreOptions? core = null)
    {
        var factory = new SingleClientFactory(new HttpClient(handler));
        return new TokenRefreshService(
            factory,
            discovery ?? new StubDiscoveryService(null),
            Options.Create(config ?? new SessionAuthenticationConfiguration()),
            Options.Create(core ?? new PortaCoreOptions()),
            NullLogger<TokenRefreshService>.Instance);
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

    private sealed class StubDiscoveryService(OpenIdConnectConfiguration? config) : IDiscoveryService
    {
        public int Calls { get; private set; }

        public Task<OpenIdConnectConfiguration?> GetConfigurationAsync(string authority, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(config);
        }
    }
}
