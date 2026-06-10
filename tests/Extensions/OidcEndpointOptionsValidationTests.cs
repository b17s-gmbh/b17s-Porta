using b17s.Porta.Extensions;
using b17s.Porta.Middleware;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// P1-9 regression: a misconfigured <c>DefaultRedirectUri</c> would silently
/// bypass the runtime open-redirect guard, because the guard runs only on
/// caller-supplied URIs and the default is the fallback when none is supplied.
/// Misconfiguration must fail the app at startup, not silently exfiltrate users.
/// </summary>
public class OidcEndpointOptionsValidationTests
{
    [Theory]
    [InlineData("//evil.com")]
    [InlineData("/\\evil.com")]
    [InlineData("https://evil.com")]
    [InlineData("http://app.example.com")]
    [InlineData("not-a-uri")]
    [InlineData("")]
    public void UseOidcLogin_InvalidDefaultRedirectUri_ThrowsAtStartup(string uri)
    {
        var app = BuildApp();

        Assert.Throws<OptionsValidationException>(() =>
            app.UseOidcLogin(configureOptions: o => o.DefaultRedirectUri = uri));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/dashboard")]
    [InlineData("/dashboard/admin?x=1")]
    public void UseOidcLogin_SafeRelativeDefaultRedirectUri_Succeeds(string uri)
    {
        var app = BuildApp();

        app.UseOidcLogin(configureOptions: o => o.DefaultRedirectUri = uri);
    }

    [Fact]
    public void UseOidcLogin_AbsoluteHttpsUri_OnAllowList_Succeeds()
    {
        var app = BuildApp();

        app.UseOidcLogin(configureOptions: o =>
        {
            o.DefaultRedirectUri = "https://app.example.com/home";
            o.AllowedRedirectHosts = ["app.example.com"];
        });
    }

    [Fact]
    public void UseOidcLogin_AbsoluteHttpsUri_NotOnAllowList_ThrowsAtStartup()
    {
        var app = BuildApp();

        var ex = Assert.Throws<OptionsValidationException>(() =>
            app.UseOidcLogin(configureOptions: o =>
            {
                o.DefaultRedirectUri = "https://app.example.com/home";
                o.AllowedRedirectHosts = ["other.example.com"];
            }));

        Assert.Contains("DefaultRedirectUri", ex.Message);
        Assert.Contains("app.example.com", ex.Message);
    }

    [Theory]
    [InlineData("//evil.com")]
    [InlineData("https://evil.com")]
    [InlineData("")]
    public void UseOidcLogout_InvalidDefaultRedirectUri_ThrowsAtStartup(string uri)
    {
        var app = BuildApp();

        Assert.Throws<OptionsValidationException>(() =>
            app.UseOidcLogout(configureOptions: o => o.DefaultRedirectUri = uri));
    }

    [Fact]
    public void UseOidcLogout_DefaultOptions_Succeed()
    {
        // The built-in default ("/") must remain valid - otherwise every caller
        // who doesn't override DefaultRedirectUri would crash at startup.
        var app = BuildApp();

        app.UseOidcLogout();
        app.UseOidcLogin();
    }

    [Fact]
    public async Task UseOidcLogout_GlobalLogout_WithSaveTokensFalse_ThrowsAtStartup()
    {
        // P2-8 regression: SignOutAsync(OpenIdConnect) populates id_token_hint
        // from the saved tokens on the auth ticket. Without SaveTokens=true the
        // hint is missing and IdPs may reject the end-session request - fail at
        // startup instead of producing broken logout flows in production.
        //
        // The SaveTokens precondition is verified asynchronously by
        // OidcEndpointStartupCheck (an IHostedService) rather than synchronously
        // during UseOidcLogout, because IAuthenticationSchemeProvider.GetSchemeAsync
        // is async-by-contract and blocking on it would deadlock a custom async
        // scheme provider. Drive the hosted check directly here.
        var app = BuildAppWithOidc(saveTokens: false);
        app.UseOidcLogout(configureOptions: o => o.PerformGlobalLogout = true);

        var startupCheck = app.ApplicationServices.GetServices<IHostedService>()
            .OfType<OidcEndpointStartupCheck>()
            .Single();

        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() =>
            startupCheck.StartAsync(TestContext.Current.CancellationToken));

        Assert.Contains("SaveTokens", ex.Message);
    }

    [Fact]
    public async Task UseOidcLogout_GlobalLogout_WithSaveTokensTrue_Succeeds()
    {
        var app = BuildAppWithOidc(saveTokens: true);
        app.UseOidcLogout(configureOptions: o => o.PerformGlobalLogout = true);

        var startupCheck = app.ApplicationServices.GetServices<IHostedService>()
            .OfType<OidcEndpointStartupCheck>()
            .Single();

        await startupCheck.StartAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public void UseOidcLogout_LocalLogout_WithSaveTokensFalse_Succeeds()
    {
        // Local-only logout doesn't touch the IdP, so SaveTokens is irrelevant.
        var app = BuildAppWithOidc(saveTokens: false);

        app.UseOidcLogout(configureOptions: o => o.PerformGlobalLogout = false);
    }

    // Back-channel logout: turning off signature / issuer / audience validation
    // would let an anonymous caller terminate any session. The settings exist as
    // a Development debugging affordance only - outside Development, startup must fail.
    [Theory]
    [InlineData("Production", true)]
    [InlineData("Staging", true)]
    [InlineData("Development", false)]
    public void UseOidcBackChannelLogout_ValidateSignatureFalse_FailsOutsideDevelopment(string environmentName, bool shouldThrow)
    {
        var app = BuildAppWithEnvironment(environmentName);

        var act = () => app.UseOidcBackChannelLogout(configureOptions: o => o.ValidateSignature = false);

        if (shouldThrow)
        {
            var ex = Assert.Throws<OptionsValidationException>(act);
            Assert.Contains("ValidateSignature", ex.Message);
        }
        else
        {
            act();
        }
    }

    [Fact]
    public void UseOidcBackChannelLogout_ValidateIssuerFalse_FailsOutsideDevelopment()
    {
        var app = BuildAppWithEnvironment("Production");

        var ex = Assert.Throws<OptionsValidationException>(() =>
            app.UseOidcBackChannelLogout(configureOptions: o => o.ValidateIssuer = false));

        Assert.Contains("ValidateIssuer", ex.Message);
    }

    [Fact]
    public void UseOidcBackChannelLogout_ValidateAudienceFalse_FailsOutsideDevelopment()
    {
        var app = BuildAppWithEnvironment("Production");

        var ex = Assert.Throws<OptionsValidationException>(() =>
            app.UseOidcBackChannelLogout(configureOptions: o => o.ValidateAudience = false));

        Assert.Contains("ValidateAudience", ex.Message);
    }

    [Fact]
    public void UseOidcBackChannelLogout_ValidateSignatureFalse_NoHostEnvironment_FailsClosed()
    {
        // L18 regression: a bare-container host without a registered IHostEnvironment
        // must be treated as production - the hardening check fails closed, not open.
        var app = BuildApp();

        var ex = Assert.Throws<OptionsValidationException>(() =>
            app.UseOidcBackChannelLogout(configureOptions: o => o.ValidateSignature = false));

        Assert.Contains("ValidateSignature", ex.Message);
    }

    [Fact]
    public void UseOidcBackChannelLogout_DefaultOptions_NoHostEnvironment_Succeeds()
    {
        // Fail-closed only bites when validation is actually disabled - secure
        // defaults must keep working in hosts without IHostEnvironment.
        var app = BuildApp();

        app.UseOidcBackChannelLogout();
    }

    [Fact]
    public void UseOidcLogin_WithoutAddOidcEndpoints_ThrowsFriendlyGuard()
    {
        // Without the guard this surfaced as an opaque "Unable to resolve service
        // for type 'IReturnUrlProtector'" at pipeline build time.
        var services = new ServiceCollection();
        services.AddLogging();
        var app = new ApplicationBuilder(services.BuildServiceProvider());

        var ex = Assert.Throws<InvalidOperationException>(() => app.UseOidcLogin());

        Assert.Contains("AddOidcEndpoints", ex.Message);
    }

    [Fact]
    public void UseOidcBackChannelLogout_AllValidationDisabled_FailsWithCombinedMessage()
    {
        var app = BuildAppWithEnvironment("Production");

        var ex = Assert.Throws<OptionsValidationException>(() =>
            app.UseOidcBackChannelLogout(configureOptions: o =>
            {
                o.ValidateSignature = false;
                o.ValidateIssuer = false;
                o.ValidateAudience = false;
            }));

        Assert.Contains("ValidateSignature", ex.Message);
        Assert.Contains("ValidateIssuer", ex.Message);
        Assert.Contains("ValidateAudience", ex.Message);
    }

    private static IApplicationBuilder BuildApp()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services.AddOidcEndpoints();

        return new ApplicationBuilder(services.BuildServiceProvider());
    }

    private static IApplicationBuilder BuildAppWithEnvironment(string environmentName)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services.AddOidcEndpoints();
        services.AddSingleton<IHostEnvironment>(new TestHostEnvironment { EnvironmentName = environmentName });

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

    private static IApplicationBuilder BuildAppWithOidc(bool saveTokens)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services.AddOidcEndpoints();

        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie()
            .AddOpenIdConnect(options =>
            {
                options.Authority = "https://idp.example.com";
                options.ClientId = "test";
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.SaveTokens = saveTokens;
            });

        return new ApplicationBuilder(services.BuildServiceProvider());
    }
}
