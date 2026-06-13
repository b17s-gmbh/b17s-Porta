using Microsoft.Playwright;

using Xunit;

namespace Demo.E2E.Tests;

/// <summary>
/// Full interactive OIDC login against Zitadel (the auto-provisioned client) driven by a real
/// headless browser. Zitadel uses a two-step login (login name, then password).
///
/// Selectors target Zitadel's classic hosted login. If you run a Zitadel version with the new
/// (Next.js) login UI, adjust the selectors below.
/// </summary>
[Collection(DemoCollection.Name)]
public sealed class ZitadelLoginTests(AppHostFixture fixture)
{
    [Fact]
    public async Task Interactive_login_establishes_an_authenticated_bff_session()
    {
        await using var context = await fixture.Browser.NewContextAsync(
            new BrowserNewContextOptions { IgnoreHTTPSErrors = true });
        var page = await context.NewPageAsync();

        await page.GotoAsync($"{DemoEndpoints.BffZitadel}/bff/login");

        // Step 1: login name.
        await page.FillAsync("input[name='loginName']", DemoEndpoints.ZitadelUser);
        await page.ClickAsync("#submit-button");

        // Step 2: password.
        await page.FillAsync("input[name='password']", DemoEndpoints.ZitadelPassword);
        await page.ClickAsync("#submit-button");

        // A fresh user may be offered optional MFA setup — skip it if present.
        await TrySkipMfaPromptAsync(page);

        await page.WaitForURLAsync(
            url => url.StartsWith(DemoEndpoints.BffZitadel, StringComparison.Ordinal),
            new PageWaitForURLOptions { Timeout = 45_000 });

        var response = await page.GotoAsync($"{DemoEndpoints.BffZitadel}/bff/user");
        Assert.NotNull(response);
        Assert.Equal(200, response!.Status);

        var body = await response.TextAsync();
        Assert.Contains("\"authenticated\":true", body);
    }

    private static async Task TrySkipMfaPromptAsync(IPage page)
    {
        try
        {
            // Zitadel's "Set up later"/skip control on the optional MFA-init step.
            var skip = page.Locator("#skip-button, button:has-text(\"skip\")");
            if (await skip.CountAsync() > 0)
            {
                await skip.First.ClickAsync(new LocatorClickOptions { Timeout = 5_000 });
            }
        }
        catch (PlaywrightException)
        {
            // No MFA prompt — nothing to skip.
        }
    }
}
