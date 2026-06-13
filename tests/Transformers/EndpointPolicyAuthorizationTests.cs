using System.Net;
using System.Security.Claims;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Tests.Fixtures;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Regression for #14 (runtime authorization-policy enforcement). The endpoint builders
/// re-evaluate a configured authorization policy inside the handler - not just at
/// authentication - so a post-<c>Build()</c> <c>.AllowAnonymous()</c> that strips
/// <c>RequireAuthorization(policy)</c> from the route metadata cannot downgrade a
/// policy-protected endpoint to "any authenticated user".
/// <para/>
/// The existing smuggling tests only cover the <em>unauthenticated → 401</em> vector. These
/// cover the <em>authenticated-but-policy-fails → 403</em> vector for both the transformer and
/// raw-forward builders, asserting the body never runs.
/// </summary>
public sealed class EndpointPolicyAuthorizationTests
{
    private const string AdminPolicy = "admin-only";

    [Fact]
    public async Task Transformer_AuthenticatedButPolicyFails_Returns403_AndBodyNeverRuns()
    {
        var transformer = new RecordingTransformer();
        var backend = new MockBackendCaller();
        using var bff = await CreateTransformerBffAsync(transformer, backend);
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/secret", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(transformer.WasInvoked, "Transformer must not run when the authorization policy fails.");
        Assert.Empty(backend.RecordedCalls);
    }

    [Fact]
    public async Task RawForward_AuthenticatedButPolicyFails_Returns403_AndBackendNeverCalled()
    {
        var transformer = new RecordingRawTransformer();
        var backend = new MockBackendCaller();
        using var bff = await CreateRawForwardBffAsync(transformer, backend);
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/raw/secret", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(backend.RecordedCalls);
    }

    private static async Task<IHost> CreateTransformerBffAsync(RecordingTransformer transformer, MockBackendCaller backend)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization(options =>
                        options.AddPolicy(AdminPolicy, policy => policy.RequireClaim("role", "admin")));
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<IBackendCaller>(backend);
                    services.AddSingleton(transformer);
                });
                webHost.Configure(app =>
                {
                    app.UseAuthenticatedNonAdmin();
                    app.UseRouting();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapTransformer<RecordingTransformer, EmptyResponse>()
                            .FromGet("/secret")
                            .ToBackend("GET", "https://backend.test/secret")
                            .RequireAuth(AdminPolicy)
                            .Build()
                            // Smuggle AllowAnonymous() onto the returned builder. Without the
                            // handler-level policy re-check this would strip RequireAuthorization(policy)
                            // and let an authenticated-but-unauthorized caller through.
                            .AllowAnonymous();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    private static async Task<IHost> CreateRawForwardBffAsync(RecordingRawTransformer transformer, MockBackendCaller backend)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization(options =>
                        options.AddPolicy(AdminPolicy, policy => policy.RequireClaim("role", "admin")));
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<IBackendCaller>(backend);
                    services.AddSingleton(transformer);
                });
                webHost.Configure(app =>
                {
                    app.UseAuthenticatedNonAdmin();
                    app.UseRouting();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapRawForward<RecordingRawTransformer>()
                            .FromGet("/raw/secret")
                            .ToBackend("GET", "https://backend.test/raw/secret")
                            .RequireAuth(AdminPolicy)
                            .Build()
                            .AllowAnonymous();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    [RequiresAuthentication]
    private sealed class RecordingTransformer : ITransformer<EmptyResponse>
    {
        public bool WasInvoked { get; private set; }

        public Task<EmptyResponse> TransformAsync(TransformerContext context)
        {
            WasInvoked = true;
            return Task.FromResult(new EmptyResponse());
        }
    }

    [RequiresAuthentication]
    private sealed class RecordingRawTransformer : IRawTransformer
    {
    }

    public sealed class EmptyResponse { }

    private sealed class AnonymousAuthProvider : IAuthenticationProvider
    {
        public Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(AuthenticationContext.Unauthenticated());

        public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
            => Task.FromResult<AuthenticationContext?>(null);

        public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}

internal static class AuthenticatedNonAdminMiddlewareExtensions
{
    /// <summary>
    /// Populates an authenticated principal that lacks the "admin" role, so the
    /// request reaches the endpoint handler authenticated but failing the policy.
    /// </summary>
    public static IApplicationBuilder UseAuthenticatedNonAdmin(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            var identity = new ClaimsIdentity(
                [new Claim(ClaimTypes.Name, "alice")],
                authenticationType: "Test");
            context.User = new ClaimsPrincipal(identity);
            await next();
        });
}
