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
/// Regression for the auth-metadata smuggling vector flagged in code review B2.
/// <para/>
/// <c>Build()</c> returns a <see cref="RouteHandlerBuilder"/>. ASP.NET Core's authorization
/// middleware honors <see cref="IAllowAnonymous"/> metadata regardless of attach order, so
/// a caller could chain <c>.AllowAnonymous()</c> onto the returned builder and silently
/// strip <c>RequireAuthorization()</c> from an endpoint marked
/// <see cref="RequiresAuthenticationAttribute"/>. The builder defends against this by
/// re-checking the authenticated principal inside the handler when the build-time
/// auth requirement was <c>true</c>.
/// </summary>
public sealed class EndpointAllowAnonymousSmugglingTests
{
    [Fact]
    public async Task Transformer_AllowAnonymousAfterBuild_StillRejectsUnauthenticatedRequest()
    {
        // The transformer is decorated with [RequiresAuthentication]. Even though the test
        // chains .AllowAnonymous() onto the post-Build() RouteHandlerBuilder (which would
        // otherwise short-circuit ASP.NET's authorization middleware), the handler-level
        // identity check must still return 401 - and the transformer body must never run.
        var transformer = new RecordingTransformer();
        using var bff = await CreateTransformerBffAsync(transformer);
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/secret", TestContext.Current.CancellationToken);

        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(transformer.WasInvoked, "Transformer must not run for unauthenticated request even after AllowAnonymous smuggling.");
    }

    [Fact]
    public async Task RawForward_AllowAnonymousAfterBuild_StillRejectsUnauthenticatedRequest()
    {
        // Same smuggling vector for raw-forward endpoints. A .AllowAnonymous() chained onto
        // the returned RouteHandlerBuilder must not bypass the [RequiresAuthentication] marker.
        var transformer = new RecordingRawTransformer();
        var backend = new MockBackendCaller();
        using var bff = await CreateRawForwardBffAsync(transformer, backend);
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/raw/secret", TestContext.Current.CancellationToken);

        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(backend.RecordedCalls);
    }

    private static async Task<IHost> CreateTransformerBffAsync(RecordingTransformer transformer)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization();
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<IBackendCaller>(new MockBackendCaller());
                    services.AddSingleton(transformer);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapTransformer<RecordingTransformer, EmptyResponse>()
                            .FromGet("/secret")
                            .ToBackend("GET", "https://backend.test/secret")
                            .Build()
                            // Smuggle AllowAnonymous() onto the returned builder. Without the
                            // handler-level guard this would silently strip RequireAuthorization.
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
                    services.AddAuthorization();
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<IBackendCaller>(backend);
                    services.AddSingleton(transformer);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapRawForward<RecordingRawTransformer>()
                            .FromGet("/raw/secret")
                            .ToBackend("GET", "https://backend.test/raw/secret")
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
