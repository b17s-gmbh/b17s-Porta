using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Testing;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Playwright;

using Xunit;

namespace Demo.E2E.Tests;

/// <summary>
/// Boots the entire Aspire graph (Keycloak, Zitadel + Postgres, the provisioner, the backend,
/// and both BFFs) ONCE for the whole test run, waits until every identity provider and BFF is
/// actually reachable, and hands tests a headless Chromium for the interactive login flows.
///
/// Requires a container runtime (Docker/Podman) on the test machine. First run pulls the
/// Keycloak/Zitadel/Postgres images and downloads Chromium, so the startup budget is generous.
/// </summary>
public sealed class AppHostFixture : IAsyncLifetime
{
    private DistributedApplication? _app;
    private IPlaywright? _playwright;

    public IBrowser Browser { get; private set; } = null!;

    /// <summary>Plain HTTP client (no browser) for unauthenticated / API assertions.</summary>
    public HttpClient Http { get; } = new() { Timeout = TimeSpan.FromSeconds(30) };

    public async ValueTask InitializeAsync()
    {
        var appHostBuilder = await DistributedApplicationTestingBuilder
            .CreateAsync<Projects.Demo_AppHost>();

        _app = await appHostBuilder.BuildAsync();
        await _app.StartAsync();

        var startupBudget = TimeSpan.FromMinutes(10);
        using var cts = new CancellationTokenSource(startupBudget);

        var notifications = _app.Services.GetRequiredService<ResourceNotificationService>();

        // Wait for the long-lived resources to report healthy.
        foreach (var resource in new[] { "keycloak", "zitadel", "backend", "bff-keycloak", "bff-zitadel" })
        {
            await notifications.WaitForResourceHealthyAsync(resource, cts.Token);
        }

        // Definitive readiness gate: the IdP discovery documents and BFF landing pages must
        // answer 200 before any login attempt.
        await PollUntilOkAsync(DemoEndpoints.KeycloakDiscovery, cts.Token);
        await PollUntilOkAsync(DemoEndpoints.ZitadelDiscovery, cts.Token);
        await PollUntilOkAsync($"{DemoEndpoints.BffKeycloak}/", cts.Token);
        await PollUntilOkAsync($"{DemoEndpoints.BffZitadel}/", cts.Token);

        // Bootstrap Playwright (downloads Chromium on first run).
        var exitCode = Microsoft.Playwright.Program.Main(["install", "chromium"]);
        if (exitCode != 0)
        {
            throw new InvalidOperationException(
                $"Playwright browser install failed with exit code {exitCode}.");
        }

        _playwright = await Playwright.CreateAsync();
        Browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
    }

    public async ValueTask DisposeAsync()
    {
        if (Browser is not null)
        {
            await Browser.CloseAsync();
        }
        _playwright?.Dispose();
        Http.Dispose();

        if (_app is not null)
        {
            await _app.DisposeAsync();
        }
    }

    private async Task PollUntilOkAsync(string url, CancellationToken ct)
    {
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var resp = await Http.GetAsync(url, ct);
                if (resp.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (HttpRequestException)
            {
                // Not up yet.
            }
            await Task.Delay(TimeSpan.FromSeconds(2), ct);
        }
    }
}

/// <summary>xUnit collection so the expensive <see cref="AppHostFixture"/> is shared by all tests.</summary>
[CollectionDefinition(Name)]
public sealed class DemoCollection : ICollectionFixture<AppHostFixture>
{
    public const string Name = "demo-apphost";
}
