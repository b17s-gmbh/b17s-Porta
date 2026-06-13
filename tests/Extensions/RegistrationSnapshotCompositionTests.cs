using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

// Regression: registration-time snapshots used to drive startup wiring (cookie/OIDC handler
// options, backend/token HttpClient timeout + resilience) were built only from the locally
// passed delegate. A caller composing options through the standard pipeline
// (Configure<T>/PostConfigure<T>) could therefore have IOptions<T> validate correctly while the
// handler-level wiring still used empty/default values. The wiring now binds lazily from the
// composed IOptions<T> pipeline, so external composition is honored everywhere.
public class RegistrationSnapshotCompositionTests
{
    [Fact]
    public void AddPortaAuthentication_NoAction_AfterExternalConfigure_BindsOidcHandler()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        // Compose the configuration entirely through the standard options pipeline, then call
        // the no-action overload. Previously this produced an EMPTY handler snapshot.
        services.Configure<SessionAuthenticationConfiguration>(c =>
        {
            c.Authority = "https://idp.example.com";
            c.ClientId = "porta-bff";
            c.ClientSecret = "porta-bff-secret";
            c.Scope = "openid profile email";
        });
        services.AddPortaAuthentication();

        var sp = services.BuildServiceProvider();
        var oidc = sp.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        Assert.Equal("porta-bff", oidc.ClientId);
        Assert.Equal("porta-bff-secret", oidc.ClientSecret);
        Assert.Equal("https://idp.example.com", oidc.Authority);
        Assert.Contains("openid", oidc.Scope);
    }

    [Fact]
    public void AddPortaAuthentication_PostConfigure_ComposesOntoCookieHandler()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddPortaAuthentication(c =>
        {
            c.Authority = "https://idp.example.com";
            c.ClientId = "porta-bff";
            c.ClientSecret = "porta-bff-secret";
            c.CookieName = "initial.cookie";
        });
        // A PostConfigure registered after the Add* call must still reach the handler.
        services.PostConfigure<SessionAuthenticationConfiguration>(c => c.CookieName = "overridden.cookie");

        var sp = services.BuildServiceProvider();
        var cookie = sp.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);

        Assert.Equal("overridden.cookie", cookie.Cookie.Name);
    }

    [Fact]
    public void AddPortaCore_PostConfigure_ComposesOntoBackendHttpClientTimeout()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddPortaCore(o => o.DefaultTimeout = TimeSpan.FromSeconds(10));
        // A PostConfigure registered after AddPortaCore must drive the HttpClient timeout.
        services.PostConfigure<PortaCoreOptions>(o => o.DefaultTimeout = TimeSpan.FromSeconds(42));

        var sp = services.BuildServiceProvider();
        var client = sp.GetRequiredService<IHttpClientFactory>().CreateClient(BackendCaller.HttpClientName);

        Assert.Equal(TimeSpan.FromSeconds(42), client.Timeout);
    }
}
