using System.Net;
using System.Net.Http.Json;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace b17s.Porta.Tests.Auth.Tokens;

public class ApiTokenServiceTests
{
    [Fact]
    public async Task GetApiTokenAsync_ExpiredCachedToken_RefreshesUsingRefreshTokenGrant()
    {
        // Regression for P0-1: the refresh path used to be wired to
        // ITokenExchangeService and issued grant_type=token-exchange with the
        // refresh token in subject_token. Cached API tokens never refreshed -
        // they always re-exchanged. Verify the IdP now sees grant_type=refresh_token.
        var apiConfig = new ApiConfiguration
        {
            ApiPath = "/api/orders",
            ApiScopes = "orders.read",
            ApiAudience = "orders-api",
            ClientId = "orders-client",
            ClientSecret = "orders-secret",
            TokenEndpoint = "https://idp.test/connect/token",
        };

        var cacheKey = "porta.api_access_token";
        var storage = new InMemoryTokenStorage();
        var httpContext = new DefaultHttpContext();

        // Prime the cache with an expired token that has a refresh token.
        var expired = new TokenExchangeResponse
        {
            AccessToken = "expired-api-access",
            RefreshToken = "stored-refresh-token",
            ExpiresIn = 3600,
            IssuedAt = DateTimeOffset.UtcNow.AddHours(-2), // makes IsExpiredWithSkew true
        };
        await storage.SetObjectAsync(httpContext, cacheKey, new Dictionary<string, TokenExchangeResponse>
        {
            [apiConfig.ApiPath] = expired,
        });

        var capture = new CapturingHandler(new TokenExchangeResponse
        {
            AccessToken = "fresh-api-access",
            RefreshToken = "rotated-refresh-token",
            ExpiresIn = 3600,
            TokenType = "Bearer",
        });
        var refreshService = new TokenRefreshService(
            new SingleClientFactory(new HttpClient(capture)),
            new UnusedDiscoveryService(),
            Microsoft.Extensions.Options.Options.Create(new SessionAuthenticationConfiguration()),
            Microsoft.Extensions.Options.Options.Create(new PortaCoreOptions()),
            NullLogger<TokenRefreshService>.Instance);

        var sut = new ApiTokenService(
            new ThrowingTokenExchangeService(), // exchange path must not be hit
            refreshService,
            storage,
            Microsoft.Extensions.Options.Options.Create(new SessionAuthenticationConfiguration()),
            Microsoft.Extensions.Options.Options.Create(new PortaCoreOptions()),
            NullLogger<ApiTokenService>.Instance);

        var result = await sut.GetApiTokenAsync(
            httpContext,
            apiConfig,
            "user-access-token",
            new ApiTokenCacheOptions { CacheKey = cacheKey },
            TestContext.Current.CancellationToken);

        Assert.Equal("fresh-api-access", result);
        Assert.NotNull(capture.LastRequest);
        Assert.Equal(apiConfig.TokenEndpoint, capture.LastRequest!.RequestUri!.ToString());
        Assert.Equal("refresh_token", capture.LastForm!["grant_type"]);
        Assert.Equal("stored-refresh-token", capture.LastForm["refresh_token"]);
        Assert.Equal(apiConfig.ClientId, capture.LastForm["client_id"]);
        Assert.Equal(apiConfig.ClientSecret, capture.LastForm["client_secret"]);
        Assert.Equal(apiConfig.ApiScopes, capture.LastForm["scope"]);
        // The token-exchange-only fields must not appear on the refresh wire.
        Assert.False(capture.LastForm.ContainsKey("subject_token"));
        Assert.False(capture.LastForm.ContainsKey("requested_token_type"));
    }

    private sealed class CapturingHandler(TokenExchangeResponse response) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public Dictionary<string, string>? LastForm { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            if (request.Content is FormUrlEncodedContent)
            {
                var body = await request.Content.ReadAsStringAsync(cancellationToken);
                LastForm = body.Split('&')
                    .Select(kv => kv.Split('=', 2))
                    .ToDictionary(parts => Uri.UnescapeDataString(parts[0]), parts => Uri.UnescapeDataString(parts[1]));
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(response),
            };
        }
    }

    private sealed class SingleClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class InMemoryTokenStorage : ITokenStorage
    {
        private readonly Dictionary<string, string> _strings = new();
        private readonly Dictionary<string, object> _objects = new();

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
            => Task.FromResult(_objects.TryGetValue(key, out var v) ? v as T : null);

        public Task<bool> SetObjectAsync<T>(HttpContext context, string key, T value) where T : class
        {
            _objects[key] = value;
            return Task.FromResult(true);
        }

        public Task RemoveObjectAsync(HttpContext context, string key)
        {
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

    private sealed class ThrowingTokenExchangeService : ITokenExchangeService
    {
        public Task<TokenExchangeResult> ExchangeAsync(string accessToken, ApiConfiguration apiConfig, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("ExchangeAsync must not be called on the refresh path");
    }

    private sealed class UnusedDiscoveryService : IDiscoveryService
    {
        public Task<Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration?> GetConfigurationAsync(string authority, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("Discovery should not be called when refresh options are explicit");
    }
}
