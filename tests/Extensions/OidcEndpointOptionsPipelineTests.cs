using b17s.Porta.Extensions;
using b17s.Porta.Middleware;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// M6 regression: AddOidcEndpoints used to register decoy
/// <c>Configure&lt;TOptions&gt;(_ =&gt; { })</c> stubs while every Use* call built its
/// options locally - idiomatic <c>services.Configure&lt;OidcLoginOptions&gt;(...)</c>
/// never reached the middleware. Use* now builds the effective options through
/// IOptionsFactory: DI composition first, per-call lambda last (wins on conflicts),
/// fresh instance per call.
/// </summary>
public class OidcEndpointOptionsPipelineTests
{
    [Fact]
    public void UseOidcLogin_HonorsDiConfiguredOptions()
    {
        // Observable through startup validation: the DI-configured (invalid) redirect
        // URI must reach UseOidcLogin's open-redirect guard.
        var app = BuildApp(s =>
            s.Configure<OidcLoginOptions>(o => o.DefaultRedirectUri = "https://evil.example.com"));

        Assert.Throws<OptionsValidationException>(() => app.UseOidcLogin());
    }

    [Fact]
    public void UseOidcLogin_PerCallLambda_WinsOverDiConfiguration()
    {
        var app = BuildApp(s =>
            s.Configure<OidcLoginOptions>(o => o.DefaultRedirectUri = "https://evil.example.com"));

        // The per-call lambda runs last and replaces the DI-configured value.
        app.UseOidcLogin(configureOptions: o => o.DefaultRedirectUri = "/dashboard");
    }

    [Fact]
    public void UseOidcLogin_TwoCalls_DoNotShareOptionsState()
    {
        var app = BuildApp();

        // First endpoint allow-lists its absolute default redirect.
        app.UseOidcLogin("/bff/login", o =>
        {
            o.DefaultRedirectUri = "https://app.example.com/home";
            o.AllowedRedirectHosts = ["app.example.com"];
        });

        // Second endpoint sets the same absolute default but no allow-list: it must
        // fail - succeeding would mean the first call's allow-list leaked across calls.
        Assert.Throws<OptionsValidationException>(() =>
            app.UseOidcLogin("/bff/login2", o =>
                o.DefaultRedirectUri = "https://app.example.com/home"));
    }

    [Fact]
    public void UseOidcLogout_HonorsDiConfiguredOptions()
    {
        var app = BuildApp(s =>
            s.Configure<OidcLogoutOptions>(o => o.DefaultRedirectUri = "https://evil.example.com"));

        Assert.Throws<OptionsValidationException>(() => app.UseOidcLogout());
    }

    [Fact]
    public void UseOidcBackChannelLogout_HonorsDiConfiguredOptions()
    {
        var app = BuildApp(s =>
        {
            s.Configure<OidcBackChannelLogoutOptions>(o => o.ValidateSignature = false);
            s.AddSingleton<IHostEnvironment>(new TestHostEnvironment());
        });

        var ex = Assert.Throws<OptionsValidationException>(() => app.UseOidcBackChannelLogout());
        Assert.Contains("ValidateSignature", ex.Message);
    }

    [Fact]
    public void UseSessionAdmin_HonorsDiConfiguredRequirePolicy()
    {
        var app = BuildApp(s =>
        {
            s.AddAuthorization(o => o.AddPolicy("AdminOnly", p => p.RequireRole("Admin")));
            s.Configure<SessionAdminOptions>(o => o.RequirePolicy = "AdminOnly");
        });

        // Previously this threw "UseSessionAdmin requires an authorization policy"
        // because the DI-configured policy never reached the Use* call.
        app.UseSessionAdmin();
    }

    private static IApplicationBuilder BuildApp(Action<IServiceCollection>? configureServices = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services.AddOidcEndpoints();
        configureServices?.Invoke(services);

        return new ApplicationBuilder(services.BuildServiceProvider());
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Production";
        public string ApplicationName { get; set; } = "test";
        public string ContentRootPath { get; set; } = "/";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; }
            = new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
