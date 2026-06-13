using b17s.Porta.Auth.Providers;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Services;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// The Add* composites are documented as idempotent: repeated calls compose options
/// through the options pipeline but must register services only once. Before the
/// marker guards, a second call nested an extra resilience handler on the named
/// HttpClients (doubling the Accept header), duplicated service descriptors, and a
/// second AddCookie()/AddOpenIdConnect()/AddJwtBearer() threw
/// "Scheme already exists" at the first authentication resolve.
/// </summary>
public class CompositeRegistrationIdempotencyTests
{
    [Fact]
    public void AddPortaCore_Twice_DoesNotDuplicateServiceDescriptors()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();

        services.AddPortaCore();
        services.AddPortaCore();

        Assert.Single(services, d => d.ServiceType == typeof(IBackendCaller));
        Assert.Single(services, d => d.ServiceType == typeof(ITrustedHostValidator));
        Assert.Single(services, d => d.ServiceType == typeof(b17s.Porta.Telemetry.PortaMetrics));
    }

    [Fact]
    public void AddPortaCore_Twice_NamedClientsConfiguredOnce()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();

        services.AddPortaCore();
        services.AddPortaCore();

        var sp = services.BuildServiceProvider();
        var factory = sp.GetRequiredService<IHttpClientFactory>();

        // A duplicated registration accumulates the configure action on the named
        // HttpClientFactoryOptions, doubling the Accept header (and nesting a second
        // resilience handler on the retry client via the same mechanism).
        var plain = factory.CreateClient(BackendCaller.HttpClientName);
        var retrying = factory.CreateClient(BackendCaller.HttpClientNameWithRetries);
        Assert.Single(plain.DefaultRequestHeaders.Accept);
        Assert.Single(retrying.DefaultRequestHeaders.Accept);
    }

    [Fact]
    public void AddPortaCore_Twice_OptionsStillCompose()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();

        services.AddPortaCore(options => options.DefaultTimeout = TimeSpan.FromSeconds(7));
        services.AddPortaCore(options => options.MaxRetryAttempts = 9);

        var sp = services.BuildServiceProvider();
        var options = sp.GetRequiredService<IOptions<PortaCoreOptions>>().Value;

        Assert.Equal(TimeSpan.FromSeconds(7), options.DefaultTimeout);
        Assert.Equal(9, options.MaxRetryAttempts);
    }

    [Fact]
    public async Task AddPortaAuthentication_Twice_SchemesResolveWithoutDuplicates()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();

        services.AddPortaAuthentication();
        services.AddPortaAuthentication();

        var sp = services.BuildServiceProvider();

        // Resolving the scheme provider materializes AuthenticationOptions; before the
        // guard the duplicated AddCookie() threw "Scheme already exists: Cookies" here.
        var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
        Assert.NotNull(await schemeProvider.GetSchemeAsync(CookieAuthenticationDefaults.AuthenticationScheme));
        Assert.NotNull(await schemeProvider.GetSchemeAsync(OpenIdConnectDefaults.AuthenticationScheme));
    }

    [Fact]
    public void AddPortaAuthentication_Twice_RegistersSessionProviderOnce()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();

        services.AddPortaAuthentication();
        services.AddPortaAuthentication();

        Assert.Single(services, d => d.ServiceType == typeof(IAuthenticationProviderRegistration));
    }

    [Fact]
    public void AddPortaAuthentication_Twice_TokenClientConfiguredOnce()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();

        // Building the token client resolves IOptions<SessionAuthenticationConfiguration>,
        // which runs its validator - so this test needs minimally valid options.
        services.AddPortaAuthentication(config =>
        {
            config.Authority = "https://idp.example.com";
            config.ClientId = "test-client";
            config.ClientSecret = "test-secret";
        });
        services.AddPortaAuthentication();

        var sp = services.BuildServiceProvider();
        var client = sp.GetRequiredService<IHttpClientFactory>()
            .CreateClient(AuthenticationServiceExtensions.TokenHttpClientName);

        Assert.Single(client.DefaultRequestHeaders.Accept);
    }

    [Fact]
    public async Task AddPortaOidcAuth_AfterAddPortaAuthentication_SchemesResolveWithoutDuplicates()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();

        services.AddPortaAuthentication();
        services.AddPortaOidcAuth(options =>
        {
            options.Authority = "https://idp.example.com";
            options.ClientId = "test-client";
            options.ClientSecret = "test-secret";
        });

        var sp = services.BuildServiceProvider();

        var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
        Assert.NotNull(await schemeProvider.GetSchemeAsync(CookieAuthenticationDefaults.AuthenticationScheme));
        Assert.Single(services, d => d.ServiceType == typeof(IAuthenticationProviderRegistration));
    }

    [Fact]
    public void AddPortaOidcAuth_Twice_OptionsStillCompose()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();

        services.AddPortaOidcAuth(options =>
        {
            options.Authority = "https://idp.example.com";
            options.ClientId = "test-client";
        });
        services.AddPortaOidcAuth(options => options.ClientSecret = "test-secret");

        var sp = services.BuildServiceProvider();
        var options = sp.GetRequiredService<IOptions<OidcAuthOptions>>().Value;

        Assert.Equal("https://idp.example.com", options.Authority);
        Assert.Equal("test-client", options.ClientId);
        Assert.Equal("test-secret", options.ClientSecret);
        Assert.Single(services, d => d.ServiceType == typeof(IAuthenticationProviderRegistration));
    }

    [Fact]
    public async Task AddPortaJwtAuthentication_Twice_BearerSchemeResolvesWithoutDuplicates()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddPortaJwtAuthentication(options => options.Authority = "https://idp.example.com");
        services.AddPortaJwtAuthentication(options => options.ValidAudiences = ["my-porta"]);

        var sp = services.BuildServiceProvider();

        // Before the guard the duplicated AddJwtBearer() threw
        // "Scheme already exists: Bearer" when AuthenticationOptions materialized.
        var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
        Assert.NotNull(await schemeProvider.GetSchemeAsync(JwtBearerDefaults.AuthenticationScheme));
        Assert.Single(services, d => d.ServiceType == typeof(IAuthenticationProviderRegistration));

        // Both calls' options compose through the pipeline.
        var options = sp.GetRequiredService<IOptions<JwtBearerAuthOptions>>().Value;
        Assert.Equal("https://idp.example.com", options.Authority);
        Assert.Equal(["my-porta"], options.ValidAudiences);
    }

    [Fact]
    public void AddReferenceTokenAuthentication_Twice_RegistersOnce()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        // Config is split across the two calls (and kept valid under the startup
        // validator) to prove later calls still compose through the options pipeline.
        services.AddReferenceTokenAuthentication(options =>
        {
            options.Authority = "https://idp.example.com";
            options.ValidAudiences = ["api"];
        });
        services.AddReferenceTokenAuthentication(options =>
        {
            options.ClientId = "test-client";
            options.ClientSecret = "test-secret";
        });

        Assert.Single(services, d => d.ServiceType == typeof(IAuthenticationProviderRegistration));

        var sp = services.BuildServiceProvider();
        var client = sp.GetRequiredService<IHttpClientFactory>()
            .CreateClient(ReferenceTokenService.HttpClientName);
        Assert.Single(client.DefaultRequestHeaders.Accept);

        var options = sp.GetRequiredService<IOptions<ReferenceTokenAuthOptions>>().Value;
        Assert.Equal("https://idp.example.com", options.Authority);
        Assert.Equal("test-client", options.ClientId);
    }

    [Fact]
    public void AddReferenceTokenAuthentication_ConfigureResilience_ReachesIntrospectionPipeline()
    {
        // The introspection client's effective timeouts live in the standard resilience
        // pipeline (AddStandardResilienceHandler resets HttpClient.Timeout to infinite),
        // so the configureResilience hook must reach the named pipeline options.
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddReferenceTokenAuthentication(
            options =>
            {
                options.Authority = "https://idp.example.com";
                options.ClientId = "test-client";
                options.ClientSecret = "test-secret";
                options.ValidAudiences = ["api"];
            },
            configureResilience: r => r.AttemptTimeout.Timeout = TimeSpan.FromSeconds(3));

        var resilience = services.BuildServiceProvider()
            .GetRequiredService<IOptionsMonitor<HttpStandardResilienceOptions>>()
            .Get(ReferenceTokenService.HttpClientName + "-standard");

        Assert.Equal(TimeSpan.FromSeconds(3), resilience.AttemptTimeout.Timeout);
    }

    [Fact]
    public void AddReferenceTokenAuthentication_CombinedWithAddReferenceTokenService_NamedClientConfiguredOnce()
    {
        // Both entry points used to register the introspection client independently
        // behind separate markers; combining them nested a second resilience handler
        // and doubled the Accept header. The auth path now delegates to
        // AddReferenceTokenService, so the named client has a single owner.
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddReferenceTokenService();
        services.AddReferenceTokenAuthentication(options =>
        {
            options.Authority = "https://idp.example.com";
            options.ClientId = "test-client";
            options.ClientSecret = "test-secret";
            options.ValidAudiences = ["api"];
        });

        var client = services.BuildServiceProvider()
            .GetRequiredService<IHttpClientFactory>()
            .CreateClient(ReferenceTokenService.HttpClientName);

        Assert.Single(client.DefaultRequestHeaders.Accept);
    }
}
