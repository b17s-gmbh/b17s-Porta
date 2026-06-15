using b17s.Porta.Auth.Providers;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Services;
using b17s.Porta.Tests.Fixtures;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Auth.Providers;

/// <summary>
/// Verifies the <c>PortaReferenceToken</c> authentication scheme: introspecting an opaque token
/// populates <see cref="HttpContext.User"/> via the standard auth middleware, so the per-endpoint
/// principal gate (<c>RequireAuthorization</c> / Porta's default) works for reference tokens with no
/// consumer-side auth code - the same way it already does for cookie/OIDC and JWT bearer.
/// </summary>
public sealed class PortaReferenceTokenSchemeTests
{
    private const string ValidToken = "valid-opaque-token";

    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = "";
    }

    [Theory]
    [InlineData(ValidToken, HttpStatusCode.OK)]
    [InlineData("revoked", HttpStatusCode.Unauthorized)]  // introspection inactive
    [InlineData(null, HttpStatusCode.Unauthorized)]       // no credential
    public async Task Scheme_GatesPlainEndpoint_OnIntrospection(string? token, HttpStatusCode expected)
    {
        using var bff = await CreateBffAsync(app =>
            app.MapGet("/me", (HttpContext ctx) => ctx.User.FindFirst("sub")?.Value ?? "")
               .RequireAuthorization());

        var response = await GetAsync(bff, "/me", token);
        Assert.Equal(expected, response.StatusCode);

        if (expected == HttpStatusCode.OK)
        {
            // The principal carries the introspection claims.
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal("user-42", body);
        }
    }

    [Theory]
    [InlineData(ValidToken, HttpStatusCode.OK)]
    [InlineData(null, HttpStatusCode.Unauthorized)]
    public async Task Scheme_SatisfiesPortaPrincipalGate_OnPassThrough(string? token, HttpStatusCode expected)
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://api.internal/data", new EchoResponse { Echoed = "ok" });

        using var bff = await CreateBffAsync(
            app => app.MapPassThrough<EchoResponse>()   // default RequireAuthorizationByDefault = true
                .FromGet("/api/data")
                .ToBackend("GET", "https://api.internal/data")
                .Build(),
            backend);

        var response = await GetAsync(bff, "/api/data", token);
        Assert.Equal(expected, response.StatusCode);
    }

    private static async Task<HttpResponseMessage> GetAsync(IHost bff, string path, string? token)
    {
        var client = bff.GetTestServer().CreateClient();
        if (token is not null)
        {
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        }
        return await client.GetAsync(path, TestContext.Current.CancellationToken);
    }

    private static async Task<IHost> CreateBffAsync(
        Action<IEndpointRouteBuilder> configureEndpoints,
        MockBackendCaller? backend = null)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization();
                    services.AddDistributedMemoryCache();

                    // Stub introspection so the test needs no real IdP. Registered before the scheme
                    // so AddReferenceTokenService's TryAdd keeps our fake.
                    services.AddSingleton<IReferenceTokenService>(new FakeIntrospector());

                    // The headline: one registration line turns opaque tokens into a real scheme.
                    services.AddPortaReferenceTokenScheme(options =>
                    {
                        options.Authority = "https://idp.test";
                        options.ValidateAudience = false;   // binding is covered elsewhere; isolate the scheme
                        options.ValidateIssuer = false;
                    });

                    // For the pass-through path: a backend + the synthetic forwarding transformer.
                    // AuthContext for outbound is resolved by the ref-token provider (registered by
                    // AddPortaReferenceTokenScheme); here the backend needs no user identity.
                    services.AddSingleton<IBackendCaller>(backend ?? new MockBackendCaller());
                    services.TryAddTransient(typeof(BackendForwardingTransformer<>));
                    services.TryAddScoped<IAuthenticationProvider>(sp =>
                        sp.GetRequiredService<ReferenceTokenAuthProvider>());
                    services.Configure<PortaCoreOptions>(o => o.RequireAuthorizationByDefault = true);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(configureEndpoints);
                });
            });
        return await hostBuilder.StartAsync();
    }

    private sealed class FakeIntrospector : IReferenceTokenService
    {
        public Task<ReferenceTokenIntrospectionResult?> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
            => Task.FromResult<ReferenceTokenIntrospectionResult?>(token == ValidToken
                ? new ReferenceTokenIntrospectionResult { IsActive = true, Claims = { ["sub"] = "user-42" } }
                : new ReferenceTokenIntrospectionResult { IsActive = false });
    }
}
