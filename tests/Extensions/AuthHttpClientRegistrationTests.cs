using b17s.Porta.Auth.Tokens;
using b17s.Porta.Extensions;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// Locks in the contract that auth-flow services resolve through the
/// resilient named HttpClient. A silent name mismatch would downgrade every
/// auth request to the default unconfigured client - see
/// <see cref="AuthHttpClientStartupCheck"/>.
/// </summary>
public class AuthHttpClientRegistrationTests
{
    [Fact]
    public void TokenRefreshService_HttpClientName_MatchesRegisteredName()
    {
        // Pure compile-time alias check - the const must literally equal the
        // registration string. Catches a hand-typed regression in either spot.
        Assert.Equal(AuthenticationServiceExtensions.TokenHttpClientName, TokenRefreshService.HttpClientName);
    }

    [Fact]
    public void NamedTokenClient_IsRegisteredWithClientActionsAndResilienceHandler()
    {
        var sp = BuildServices().BuildServiceProvider();

        // The resilience pipeline owns the per-attempt timeout, so HttpClient.Timeout
        // on the resolved instance is InfiniteTimeSpan - checking that value would
        // not distinguish the named client from the default. Instead, assert the
        // factory options for the name have both a client action (the lambda that
        // configures Timeout/Headers) and at least one message-handler action (the
        // standard resilience handler). An unregistered name yields empty lists.
        var options = sp.GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>()
            .Get(AuthenticationServiceExtensions.TokenHttpClientName);

        Assert.NotEmpty(options.HttpClientActions);
        Assert.NotEmpty(options.HttpMessageHandlerBuilderActions);
    }

    [Fact]
    public async Task StartupCheck_Passes_WhenNamedClientIsRegistered()
    {
        var sp = BuildServices().BuildServiceProvider();
        var hostedServices = sp.GetServices<IHostedService>();
        var check = hostedServices.OfType<AuthHttpClientStartupCheck>().Single();

        // Should not throw - AddPortaAuthentication registers the named client.
        await check.StartAsync(CancellationToken.None);
    }

    [Fact]
    public async Task StartupCheck_Throws_WhenNamedClientIsMissing()
    {
        // Build a minimal service graph that wires the check but skips the
        // AddHttpClient registration - simulating the regression we are guarding against.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHttpClient(); // registers IHttpClientFactory + options infrastructure,
                                  // but no named client.
        services.AddHostedService<AuthHttpClientStartupCheck>();

        var sp = services.BuildServiceProvider();
        var check = sp.GetServices<IHostedService>().OfType<AuthHttpClientStartupCheck>().Single();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => check.StartAsync(CancellationToken.None));
        Assert.Contains(AuthenticationServiceExtensions.TokenHttpClientName, ex.Message);
    }

    private static IServiceCollection BuildServices()
    {
        var dict = new Dictionary<string, string?>
        {
            ["SessionAuthentication:Authority"] = "https://idp.example.com",
            ["SessionAuthentication:ClientId"] = "test-client",
            ["SessionAuthentication:ClientSecret"] = "test-secret",
            ["SessionAuthentication:Scope"] = "openid profile email",
            ["SessionAuthentication:CookieName"] = "TestCookie",
            ["SessionAuthentication:UsePkce"] = "true",
            ["SessionAuthentication:SessionTimeoutInMin"] = "60",
            ["SessionAuthentication:DataProtection:Enabled"] = "true",
            ["SessionAuthentication:DataProtection:ApplicationName"] = "TestApp",
            ["SessionAuthentication:DataProtection:KeyLifetimeDays"] = "30",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();
        // HaConfigurationStartupCheck (registered as a hosted service inside
        // AddPortaAuthentication) takes IHostEnvironment; the test provider needs
        // one or enumerating IHostedService fails.
        services.AddSingleton<IHostEnvironment>(new TestHostEnvironment());
        services.AddPortaAuthentication(config);
        return services;
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = nameof(AuthHttpClientRegistrationTests);
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } =
            new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
