using System.Net.Http.Headers;
using System.Text;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Regression coverage for the named/aggregated backend auth wiring. The built-in auth handlers
/// resolve per-backend credentials and token-exchange audiences via <see cref="BackendRequest.BackendName"/>,
/// so <see cref="NamedBackendEndpoint.ToBackendRequest"/> must propagate <see cref="NamedBackendEndpoint.Name"/>
/// into it. When it did not, every named backend ran with a null name: per-backend BasicAuth and
/// per-backend token exchange were unreachable, and the fail-closed guard for named-but-unconfigured
/// backends never fired — silently downgrading to global credentials (see SECURITY.md auth section).
///
/// Unlike <see cref="DefaultAuthHandlersTests"/>, which sets <c>BackendName</c> on the request directly,
/// these tests build the request through the real <c>ToBackendRequest()</c> wiring so the propagation
/// itself is exercised end-to-end.
/// </summary>
public sealed class NamedBackendEndpointAuthWiringTests
{
    private static NamedBackendEndpoint Endpoint(string name, string? authPolicy = null, string? audience = null) => new()
    {
        Name = name,
        Method = "GET",
        UrlTemplate = "https://backend.test/resource",
        BackendAuthPolicy = authPolicy,
        UseTokenExchange = audience != null,
        TokenExchangeAudience = audience,
    };

    private static BackendAuthContext ContextFor(BackendRequest request, string? accessToken = null) => new()
    {
        AccessToken = accessToken,
        BackendRequest = request,
        CancellationToken = TestContext.Current.CancellationToken,
    };

    [Fact]
    public void ToBackendRequest_PropagatesName_AsBackendName()
    {
        // The core regression: without this, every named backend reaches the auth handlers with a
        // null BackendName and per-backend resolution is dead code.
        var request = Endpoint("orders").ToBackendRequest();

        Assert.Equal("orders", request.BackendName);
    }

    [Fact]
    public async Task NamedBackend_WithPerBackendBasicAuth_UsesPerBackendCredentials_NotGlobalDefault()
    {
        var options = new BackendServiceOptions
        {
            BasicAuth = new BasicAuthOptions { Username = "default-user", Password = "default-pw" },
            Backends =
            {
                ["orders"] = new BasicAuthOptions { Username = "orders-user", Password = "orders-pw" },
            },
        };
        var handler = new BasicAuthHandler(Options.Create(options), NullLogger<BasicAuthHandler>.Instance);
        var request = Endpoint("orders", BackendAuthPolicies.BasicAuth).ToBackendRequest();
        using var httpRequest = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

        await handler.ApplyAuthAsync(httpRequest, ContextFor(request));

        AssertBasic(httpRequest, "orders-user", "orders-pw");
    }

    [Fact]
    public async Task NamedBackend_Unconfigured_FailsClosed_DoesNotLeakGlobalDefault()
    {
        // A named backend with no per-backend entry must not silently inherit the global default
        // credentials. This guard is only reachable once the backend name survives ToBackendRequest().
        var options = new BackendServiceOptions
        {
            BasicAuth = new BasicAuthOptions { Username = "default-user", Password = "default-pw" },
            Backends =
            {
                ["orders"] = new BasicAuthOptions { Username = "orders-user", Password = "orders-pw" },
            },
        };
        var handler = new BasicAuthHandler(Options.Create(options), NullLogger<BasicAuthHandler>.Instance);
        var request = Endpoint("unknown", BackendAuthPolicies.BasicAuth).ToBackendRequest();
        using var httpRequest = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

        await handler.ApplyAuthAsync(httpRequest, ContextFor(request));

        Assert.Null(httpRequest.Headers.Authorization);
    }

    [Fact]
    public async Task NamedBackend_WithPerBackendTokenExchangeAudience_UsesPerBackendAudience_NotDefault()
    {
        ApiConfiguration? captured = null;
        var apiTokenService = new CapturingApiTokenService(cfg => { captured = cfg; return "exchanged"; });
        var options = new BackendServiceOptions
        {
            DefaultTokenExchangeAudience = "default-aud",
            TokenExchangeAudiences = { ["orders"] = "per-backend-aud" },
        };
        var handler = new TokenExchangeAuthHandler(
            Options.Create(options),
            NullLogger<TokenExchangeAuthHandler>.Instance,
            new HttpContextAccessor { HttpContext = HttpContextWith(apiTokenService) });

        // No inline audience on the endpoint, so resolution must fall to the per-backend lookup
        // keyed by BackendName — which only works once Name is propagated.
        var request = Endpoint("orders", BackendAuthPolicies.TokenExchange).ToBackendRequest(accessToken: "user-token");
        using var httpRequest = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

        await handler.ApplyAuthAsync(httpRequest, ContextFor(request, accessToken: "user-token"));

        Assert.NotNull(captured);
        Assert.Equal("per-backend-aud", captured!.ApiAudience);
    }

    private static void AssertBasic(HttpRequestMessage request, string username, string password)
    {
        Assert.NotNull(request.Headers.Authorization);
        Assert.Equal("Basic", request.Headers.Authorization!.Scheme);

        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
        Assert.Equal(expected, request.Headers.Authorization.Parameter);
    }

    private static DefaultHttpContext HttpContextWith(IApiTokenService apiTokenService) => new()
    {
        RequestServices = new ServiceCollection().AddSingleton(apiTokenService).BuildServiceProvider(),
    };

    /// <summary>Captures the <see cref="ApiConfiguration"/> the handler builds so audience resolution can be asserted.</summary>
    private sealed class CapturingApiTokenService(Func<ApiConfiguration, string?> onCall) : IApiTokenService
    {
        public Task<string?> GetApiTokenAsync(
            HttpContext context,
            ApiConfiguration apiConfig,
            string? accessToken,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(onCall(apiConfig));

        public Task<string?> GetApiTokenAsync(
            HttpContext context,
            ApiConfiguration apiConfig,
            string? accessToken,
            ApiTokenCacheOptions cacheOptions,
            CancellationToken cancellationToken = default) =>
            GetApiTokenAsync(context, apiConfig, accessToken, cancellationToken);

        public Task InvalidateApiTokensAsync(HttpContext context, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task InvalidateApiTokensAsync(
            HttpContext context,
            ApiTokenCacheOptions cacheOptions,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
