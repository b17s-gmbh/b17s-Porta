using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

public class AddPortaCoreConfigurationBindingTests
{
    // Regression: the AddPortaCore(IConfiguration) overload used to Bind() onto a throwaway
    // PortaCoreOptions and then hand-copy a subset of properties into the real options. That
    // copy block silently dropped any property not listed - RefreshBackendTokenOn401,
    // TokenRefreshSkew, LogIdpErrorBodies, IdpErrorBodyMaxBytes and DefaultRawForwardHeaderPassThrough
    // were all documented appsettings keys that never took effect. Binding straight onto the
    // configure delegate's options instance must honor every property.

    [Fact]
    public void AddPortaCore_FromConfiguration_BindsEveryOption()
    {
        // Every value below is deliberately non-default so a dropped property fails the assert.
        var dict = new Dictionary<string, string?>
        {
            ["PortaCore:TrustedHosts:0"] = "https://api.example.com",
            ["PortaCore:DefaultTimeout"] = "00:00:45",
            ["PortaCore:MaxRetryAttempts"] = "7",
            ["PortaCore:RefreshBackendTokenOn401"] = "false",
            ["PortaCore:RequireAuthorizationByDefault"] = "false",
            ["PortaCore:EnableTelemetry"] = "false",
            ["PortaCore:MaxBodyLogLength"] = "256",
            ["PortaCore:MaxBackendResponseBytes"] = "2048",
            ["PortaCore:MaxRawForwardResponseBytes"] = "4096",
            ["PortaCore:RawForwardReadIdleTimeout"] = "00:00:15",
            ["PortaCore:TokenRefreshSkew"] = "00:01:30",
            ["PortaCore:LogIdpErrorBodies"] = "true",
            ["PortaCore:IdpErrorBodyMaxBytes"] = "1024",
            ["PortaCore:DefaultRawForwardHeaderPassThrough:AllowedHeaders:0"] = "X-Tenant-Id",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();

        var services = new ServiceCollection();
        services.AddPortaCore(config);

        var sp = services.BuildServiceProvider();
        var options = sp.GetRequiredService<IOptions<PortaCoreOptions>>().Value;

        // Properties the old copy block already handled - kept as a baseline.
        Assert.Equal(["https://api.example.com"], options.TrustedHosts);
        Assert.Equal(TimeSpan.FromSeconds(45), options.DefaultTimeout);
        Assert.Equal(7, options.MaxRetryAttempts);
        Assert.False(options.RequireAuthorizationByDefault);
        Assert.False(options.EnableTelemetry);
        Assert.Equal(256, options.MaxBodyLogLength);
        Assert.Equal(2048, options.MaxBackendResponseBytes);
        Assert.Equal(4096, options.MaxRawForwardResponseBytes);
        Assert.Equal(TimeSpan.FromSeconds(15), options.RawForwardReadIdleTimeout);

        // Properties the old copy block silently dropped - the actual regression.
        Assert.False(options.RefreshBackendTokenOn401);
        Assert.Equal(TimeSpan.FromSeconds(90), options.TokenRefreshSkew);
        Assert.True(options.LogIdpErrorBodies);
        Assert.Equal(1024, options.IdpErrorBodyMaxBytes);
        Assert.Contains("X-Tenant-Id", options.DefaultRawForwardHeaderPassThrough.AllowedHeaders);
    }

    // Regression: the documented "BackendService" appsettings section (BasicAuth credentials and
    // token-exchange audiences for the built-in BasicAuth/TokenExchange handlers) was never bound
    // by AddPortaCore(IConfiguration). The handlers consume IOptions<BackendServiceOptions>, so
    // consumers following the docs got empty options at runtime - silent backend-auth failures.
    [Fact]
    public void AddPortaCore_FromConfiguration_BindsBackendServiceSection()
    {
        var dict = new Dictionary<string, string?>
        {
            ["BackendService:BaseUrl"] = "https://api.internal.example.com",
            ["BackendService:BasicAuth:Username"] = "bff",
            ["BackendService:BasicAuth:Password"] = "secret",
            ["BackendService:Backends:PartnerApi:Username"] = "partner-bff",
            ["BackendService:Backends:PartnerApi:Password"] = "partner-secret",
            ["BackendService:AllowGlobalBasicAuthFallback"] = "true",
            ["BackendService:DefaultTokenExchangeAudience"] = "https://api.internal.example.com",
            ["BackendService:TokenExchangeAudiences:PartnerApi"] = "https://partner.example.com",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();

        var services = new ServiceCollection();
        services.AddPortaCore(config);

        var sp = services.BuildServiceProvider();
        var options = sp.GetRequiredService<IOptions<BackendServiceOptions>>().Value;

        Assert.Equal("https://api.internal.example.com", options.BaseUrl);
        Assert.Equal("bff", options.BasicAuth.Username);
        Assert.Equal("secret", options.BasicAuth.Password);
        Assert.True(options.AllowGlobalBasicAuthFallback);
        Assert.Equal("partner-bff", options.Backends["PartnerApi"].Username);
        Assert.Equal("partner-secret", options.Backends["PartnerApi"].Password);
        Assert.Equal("https://api.internal.example.com", options.DefaultTokenExchangeAudience);
        Assert.Equal("https://partner.example.com", options.TokenExchangeAudiences["PartnerApi"]);
    }
}
