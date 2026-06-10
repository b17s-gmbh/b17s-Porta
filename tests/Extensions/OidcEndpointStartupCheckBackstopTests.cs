using b17s.Porta.Extensions;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// L19 regression: in <c>Startup.Configure</c> / TestServer-style hosts the request pipeline is
/// built by the web host's own hosted service AFTER user-registered hosted services have started,
/// so <see cref="OidcEndpointStartupCheck"/> ran before any <c>Use*</c> call recorded its
/// requirements - and verified nothing (a silent false pass). The first-request backstop must
/// catch what the hosted check missed.
/// </summary>
public class OidcEndpointStartupCheckBackstopTests
{
    [Fact]
    public async Task UseSessionAdmin_PipelineBuiltAfterHostStart_MissingPolicy_FailsAtFirstRequest()
    {
        var provider = BuildServices(s => s.AddAuthorization());
        await RunHostedStartupCheck(provider);

        var app = new ApplicationBuilder(provider);
        app.UseSessionAdmin(configureOptions: o => o.RequirePolicy = "DoesNotExist");
        var pipeline = app.Build();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            pipeline(CreateContext(provider, "/")));
        Assert.Contains("DoesNotExist", ex.Message);

        // The failure must not be one-shot: pending requirements stay pending, so
        // every request keeps failing instead of silently passing after the first.
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            pipeline(CreateContext(provider, "/")));
    }

    [Fact]
    public async Task UseSessionAdmin_PipelineBuiltAfterHostStart_ValidPolicy_FirstRequestPasses()
    {
        var provider = BuildServices(s => s.AddAuthorization(o =>
            o.AddPolicy("Admin", p => p.RequireAssertion(_ => true))));
        await RunHostedStartupCheck(provider);

        var app = new ApplicationBuilder(provider);
        app.UseSessionAdmin(configureOptions: o => o.RequirePolicy = "Admin");
        var pipeline = app.Build();

        var context = CreateContext(provider, "/");
        await pipeline(context);

        // Verification passed and the request fell through to the terminal 404.
        Assert.Equal(StatusCodes.Status404NotFound, context.Response.StatusCode);
    }

    [Fact]
    public async Task UseOidcLogout_GlobalLogout_PipelineBuiltAfterHostStart_SaveTokensFalse_FailsAtFirstRequest()
    {
        var provider = BuildServices(s =>
            s.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie()
                .AddOpenIdConnect(o =>
                {
                    o.Authority = "https://idp.example.com";
                    o.ClientId = "test";
                    o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    o.SaveTokens = false;
                }));
        await RunHostedStartupCheck(provider);

        var app = new ApplicationBuilder(provider);
        app.UseOidcLogout(configureOptions: o => o.PerformGlobalLogout = true);
        var pipeline = app.Build();

        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            pipeline(CreateContext(provider, "/")));
        Assert.Contains("SaveTokens", ex.Message);
    }

    private static ServiceProvider BuildServices(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting(); // EndpointDataSource, needed by the UseAuthorization() branch
        services.AddDataProtection();
        services.AddOidcEndpoints();
        configure?.Invoke(services);
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Simulates GenericWebHostService ordering: hosted services start while the registry is
    /// still empty, because the pipeline (and its <c>Use*</c> recordings) doesn't exist yet.
    /// </summary>
    private static async Task RunHostedStartupCheck(ServiceProvider provider)
    {
        var check = provider.GetServices<IHostedService>()
            .OfType<OidcEndpointStartupCheck>()
            .Single();
        await check.StartAsync(TestContext.Current.CancellationToken);
    }

    private static DefaultHttpContext CreateContext(IServiceProvider provider, string path)
    {
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Path = path;
        return context;
    }
}
