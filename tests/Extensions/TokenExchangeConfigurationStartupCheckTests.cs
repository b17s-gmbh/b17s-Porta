using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// Tests for <see cref="TokenExchangeConfigurationStartupCheck"/>: it must fail fast when
/// token-exchange audiences are configured but <see cref="IApiTokenService"/> is unregistered,
/// and stay quiet otherwise.
/// </summary>
public sealed class TokenExchangeConfigurationStartupCheckTests
{
    [Fact]
    public async Task AudiencesConfigured_ButApiTokenServiceMissing_ThrowsAtStartup()
    {
        var options = Options.Create(new BackendServiceOptions { DefaultTokenExchangeAudience = "api" });
        var check = new TokenExchangeConfigurationStartupCheck(
            NullLogger<TokenExchangeConfigurationStartupCheck>.Instance,
            options,
            new FakeServiceProviderIsService(registered: false));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => check.StartAsync(TestContext.Current.CancellationToken));
        Assert.Contains("IApiTokenService", ex.Message);
    }

    [Fact]
    public async Task PerBackendAudiencesConfigured_ButApiTokenServiceMissing_ThrowsAtStartup()
    {
        var options = Options.Create(new BackendServiceOptions
        {
            TokenExchangeAudiences = { ["orders"] = "orders-api" },
        });
        var check = new TokenExchangeConfigurationStartupCheck(
            NullLogger<TokenExchangeConfigurationStartupCheck>.Instance,
            options,
            new FakeServiceProviderIsService(registered: false));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => check.StartAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AudiencesConfigured_AndApiTokenServiceRegistered_DoesNotThrow()
    {
        var options = Options.Create(new BackendServiceOptions { DefaultTokenExchangeAudience = "api" });
        var check = new TokenExchangeConfigurationStartupCheck(
            NullLogger<TokenExchangeConfigurationStartupCheck>.Instance,
            options,
            new FakeServiceProviderIsService(registered: true));

        await check.StartAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task NoTokenExchangeConfigured_DoesNotThrow_EvenWithoutApiTokenService()
    {
        var options = Options.Create(new BackendServiceOptions());
        var check = new TokenExchangeConfigurationStartupCheck(
            NullLogger<TokenExchangeConfigurationStartupCheck>.Instance,
            options,
            new FakeServiceProviderIsService(registered: false));

        await check.StartAsync(TestContext.Current.CancellationToken);
    }

    private sealed class FakeServiceProviderIsService(bool registered) : IServiceProviderIsService
    {
        public bool IsService(Type serviceType) =>
            serviceType == typeof(IApiTokenService) && registered;
    }
}
