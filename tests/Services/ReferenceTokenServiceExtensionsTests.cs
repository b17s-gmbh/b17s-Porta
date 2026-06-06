using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Services;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace b17s.Porta.Tests.Services;

/// <summary>
/// Locks in the DI wiring for <see cref="ReferenceTokenServiceExtensions.AddReferenceTokenService"/>:
/// the named HttpClient name must match <see cref="ReferenceTokenService.HttpClientName"/> exactly,
/// the standard resilience handler must be wired, and options binding must flow through.
/// </summary>
public sealed class ReferenceTokenServiceExtensionsTests
{
    [Fact]
    public void AddReferenceTokenService_RegistersIReferenceTokenService_AsSingleton()
    {
        var sp = BaseServices()
            .AddReferenceTokenService()
            .BuildServiceProvider();

        // Two resolutions inside the same root must be the same instance - singleton
        // registration is load-bearing because the cache and introspection state live
        // on the service itself.
        var a = sp.GetRequiredService<IReferenceTokenService>();
        var b = sp.GetRequiredService<IReferenceTokenService>();

        Assert.Same(a, b);
        Assert.IsType<ReferenceTokenService>(a);
    }

    [Fact]
    public void AddReferenceTokenService_NamedHttpClient_HasClientAndHandlerActions()
    {
        // The HttpClient must be registered under the exact constant name and carry
        // both: the AddHttpClient lambda (for Timeout + Accept header) AND a
        // message-handler registration (the standard resilience handler).
        // A name mismatch would silently drop both onto the default unconfigured client.
        var sp = BaseServices()
            .AddReferenceTokenService()
            .BuildServiceProvider();

        var factoryOptions = sp.GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>()
            .Get(ReferenceTokenService.HttpClientName);

        Assert.NotEmpty(factoryOptions.HttpClientActions);
        Assert.NotEmpty(factoryOptions.HttpMessageHandlerBuilderActions);
    }

    [Fact]
    public void AddReferenceTokenService_ConfigureHttpClient_IsAppliedToNamedClient()
    {
        // The configureHttpClient callback must run alongside the default Timeout/Accept
        // setup, not replace it. We assert by observing a custom DefaultRequestHeader
        // that only our callback would have added.
        var sp = BaseServices()
            .AddReferenceTokenService(
                configureHttpClient: client => client.DefaultRequestHeaders.Add("X-Test-Header", "marker"))
            .BuildServiceProvider();

        var client = sp.GetRequiredService<IHttpClientFactory>()
            .CreateClient(ReferenceTokenService.HttpClientName);

        Assert.True(client.DefaultRequestHeaders.Contains("X-Test-Header"));
        Assert.Equal("marker", client.DefaultRequestHeaders.GetValues("X-Test-Header").Single());
    }

    [Fact]
    public void AddReferenceTokenService_ConfigureOptions_PopulatesReferenceTokenAuthOptions()
    {
        // The configureOptions delegate must reach the live ReferenceTokenAuthOptions
        // via IOptionsMonitor; that's the surface ReferenceTokenService reads from on
        // every introspection so it can pick up appsettings reloads.
        var sp = BaseServices()
            .AddReferenceTokenService(
                configureOptions: o =>
                {
                    o.Authority = "https://idp.test";
                    o.ClientId = "ref-client";
                    o.ClientSecret = "ref-secret";
                    o.NegativeCacheDuration = TimeSpan.FromSeconds(7);
                })
            .BuildServiceProvider();

        var opts = sp.GetRequiredService<IOptionsMonitor<ReferenceTokenAuthOptions>>().CurrentValue;

        Assert.Equal("https://idp.test", opts.Authority);
        Assert.Equal("ref-client", opts.ClientId);
        Assert.Equal("ref-secret", opts.ClientSecret);
        Assert.Equal(TimeSpan.FromSeconds(7), opts.NegativeCacheDuration);
    }

    [Fact]
    public void AddReferenceTokenService_DefaultResilienceOptions_AreNonZero()
    {
        // The defaults configured by AddStandardResilienceHandler in the extension
        // (AttemptTimeout 10s, SamplingDuration 30s, TotalRequestTimeout 30s) should
        // be reachable via the options resolver. Important: zero would disable timeouts.
        var sp = BaseServices()
            .AddReferenceTokenService()
            .BuildServiceProvider();

        var resilience = sp.GetRequiredService<IOptionsMonitor<HttpStandardResilienceOptions>>()
            .Get(ReferenceTokenService.HttpClientName + "-standard");

        Assert.Equal(TimeSpan.FromSeconds(10), resilience.AttemptTimeout.Timeout);
        Assert.Equal(TimeSpan.FromSeconds(30), resilience.CircuitBreaker.SamplingDuration);
        Assert.Equal(TimeSpan.FromSeconds(30), resilience.TotalRequestTimeout.Timeout);
    }

    [Fact]
    public void AddReferenceTokenService_ConfigureResilience_IsAppliedAfterDefaults()
    {
        // The configureResilience delegate must run after the default settings so
        // user overrides win. Verify by overriding AttemptTimeout to a distinctive value.
        var sp = BaseServices()
            .AddReferenceTokenService(
                configureResilience: r => r.AttemptTimeout.Timeout = TimeSpan.FromSeconds(2))
            .BuildServiceProvider();

        var resilience = sp.GetRequiredService<IOptionsMonitor<HttpStandardResilienceOptions>>()
            .Get(ReferenceTokenService.HttpClientName + "-standard");

        Assert.Equal(TimeSpan.FromSeconds(2), resilience.AttemptTimeout.Timeout);
    }

    [Fact]
    public void AddReferenceTokenService_IConfigurationOverload_BindsRootConfigToOptions()
    {
        // The IConfiguration overload binds the *root* configuration directly into
        // ReferenceTokenAuthOptions - useful when callers pass a pre-sliced section.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authority"] = "https://idp.example",
                ["ClientId"] = "ref-id",
                ["ClientSecret"] = "ref-sec",
            })
            .Build();

        var sp = BaseServices()
            .AddReferenceTokenService(config)
            .BuildServiceProvider();

        var opts = sp.GetRequiredService<IOptionsMonitor<ReferenceTokenAuthOptions>>().CurrentValue;
        Assert.Equal("https://idp.example", opts.Authority);
        Assert.Equal("ref-id", opts.ClientId);
        Assert.Equal("ref-sec", opts.ClientSecret);
    }

    [Fact]
    public void AddReferenceTokenService_SectionOverload_BindsNestedSection()
    {
        // The section-name overload slices a sub-section out of the root config.
        // This is the typical wiring shape in Program.cs.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ReferenceTokenAuth:Authority"] = "https://idp.from-section",
                ["ReferenceTokenAuth:ClientId"] = "from-section-id",
                ["Authority"] = "must-not-be-picked-up",
            })
            .Build();

        var sp = BaseServices()
            .AddReferenceTokenService(config, "ReferenceTokenAuth")
            .BuildServiceProvider();

        var opts = sp.GetRequiredService<IOptionsMonitor<ReferenceTokenAuthOptions>>().CurrentValue;
        Assert.Equal("https://idp.from-section", opts.Authority);
        Assert.Equal("from-section-id", opts.ClientId);
    }

    [Fact]
    public void AddReferenceTokenService_HttpClientName_MatchesRegisteredConstant()
    {
        // Compile-time alias check: the registration uses the constant, so if a
        // future edit hardcodes a string here the const stays in sync. This locks
        // in that the constant is the single source of truth.
        Assert.Equal("ReferenceTokenIntrospection", ReferenceTokenService.HttpClientName);
    }

    private static IServiceCollection BaseServices()
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddDebug());
        services.AddOptions();
        // ReferenceTokenService takes IDiscoveryService in its constructor; the
        // extension under test doesn't register it (it's registered separately by
        // the consuming app). A stub satisfies the resolution graph so we can
        // assert singleton-ness without instantiating real discovery.
        services.AddSingleton<IDiscoveryService>(new NullDiscoveryService());
        return services;
    }

    private sealed class NullDiscoveryService : IDiscoveryService
    {
        public Task<OpenIdConnectConfiguration?> GetConfigurationAsync(string authority, CancellationToken cancellationToken = default)
            => Task.FromResult<OpenIdConnectConfiguration?>(null);
    }
}
