using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// M6 regression: IOptions&lt;OidcAuthOptions&gt; used to be write-only - AddPortaOidcAuth
/// projected a registration-time snapshot into SessionAuthenticationConfiguration, so
/// Configure/PostConfigure&lt;OidcAuthOptions&gt; (e.g. injecting ClientSecret from a secret
/// store) was a silent no-op, and the IConfiguration overload bound a one-shot snapshot
/// that never observed configuration reloads.
/// </summary>
public class AddPortaOidcAuthOptionsPipelineTests
{
    [Fact]
    public void PostConfigureOidcAuthOptions_FlowsToSessionConfiguration()
    {
        var services = CreateServices();
        services.AddPortaOidcAuth(o =>
        {
            o.Authority = "https://idp.example.com";
            o.ClientId = "porta";
            o.ClientSecret = "placeholder";
        });

        services.PostConfigure<OidcAuthOptions>(o => o.ClientSecret = "from-secret-store");

        var sp = services.BuildServiceProvider();
        var session = sp.GetRequiredService<IOptions<SessionAuthenticationConfiguration>>().Value;

        Assert.Equal("from-secret-store", session.ClientSecret);
    }

    [Fact]
    public void PostConfigureOidcAuthOptions_ReachesTheOpenIdConnectHandler()
    {
        var services = CreateServices();
        services.AddPortaCore();
        services.AddPortaOidcAuth(o =>
        {
            o.Authority = "https://idp.example.com";
            o.ClientId = "porta";
            o.ClientSecret = "placeholder";
        });

        services.PostConfigure<OidcAuthOptions>(o => o.ClientSecret = "from-secret-store");

        var sp = services.BuildServiceProvider();
        var oidc = sp.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        Assert.Equal("from-secret-store", oidc.ClientSecret);
    }

    [Fact]
    public void ConfigurationOverload_IsReloadAware()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OidcAuth:Authority"] = "https://idp.example.com",
                ["OidcAuth:ClientId"] = "porta",
                ["OidcAuth:ClientSecret"] = "v1",
            })
            .Build();

        var services = CreateServices();
        services.AddPortaOidcAuth(configuration);

        var sp = services.BuildServiceProvider();
        var monitor = sp.GetRequiredService<IOptionsMonitor<SessionAuthenticationConfiguration>>();
        Assert.Equal("v1", monitor.CurrentValue.ClientSecret);

        configuration.Providers.First().Set("OidcAuth:ClientSecret", "v2");
        configuration.Reload();

        Assert.Equal("v2", monitor.CurrentValue.ClientSecret);
    }

    private static ServiceCollection CreateServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();
        services.AddLogging();
        return services;
    }
}
