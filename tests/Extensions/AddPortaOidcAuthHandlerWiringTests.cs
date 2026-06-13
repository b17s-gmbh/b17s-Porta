using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

public class AddPortaOidcAuthHandlerWiringTests
{
    // Regression: AddPortaOidcAuth registers IOptions<SessionAuthenticationConfiguration>
    // correctly, but the OpenIdConnect *handler* (ClientId/Authority/ClientSecret/Scope) is
    // wired from a positional config snapshot at startup. A bug routed that wiring through the
    // no-arg AddPortaAuthentication(), which built an EMPTY snapshot — so the handler came up
    // with ClientId="" and OpenIdConnectOptions.Validate() threw at host start. These assertions
    // resolve the real OpenIdConnectOptions to guard the handler-level binding, not just IOptions.

    [Fact]
    public void AddPortaOidcAuth_BindsClientCredentialsOntoTheOpenIdConnectHandler()
    {
        var services = new ServiceCollection();
        services.AddOptions();
        services.AddLogging();
        services.AddPortaCore();
        services.AddPortaOidcAuth(o =>
        {
            o.Authority = "https://idp.example.com";
            o.ClientId = "porta-bff";
            o.ClientSecret = "porta-bff-secret";
            o.Scope = "openid profile email";
        });

        var sp = services.BuildServiceProvider();
        var oidc = sp.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        Assert.Equal("porta-bff", oidc.ClientId);
        Assert.Equal("porta-bff-secret", oidc.ClientSecret);
        Assert.Equal("https://idp.example.com", oidc.Authority);
        Assert.Contains("openid", oidc.Scope);
        Assert.Contains("profile", oidc.Scope);
        Assert.Contains("email", oidc.Scope);
    }
}
