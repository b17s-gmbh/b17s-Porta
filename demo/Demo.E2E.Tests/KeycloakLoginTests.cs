using Microsoft.Playwright;

using Xunit;

namespace Demo.E2E.Tests;

/// <summary>
/// Full interactive OIDC login against Keycloak driven by a real (headless) browser:
/// /bff/login → Keycloak login form → callback → authenticated BFF session.
/// </summary>
[Collection(DemoCollection.Name)]
public sealed class KeycloakLoginTests(AppHostFixture fixture)
{
    [Fact]
    public async Task Interactive_login_establishes_an_authenticated_bff_session()
    {
        await using var context = await fixture.Browser.NewContextAsync(
            new BrowserNewContextOptions { IgnoreHTTPSErrors = true });
        var page = await context.NewPageAsync();

        // Kick off the BFF login; Porta challenges and the browser lands on the Keycloak form.
        await page.GotoAsync($"{DemoEndpoints.BffKeycloak}/bff/login");

        // Keycloak's standard login theme.
        await page.FillAsync("#username", DemoEndpoints.KeycloakUser);
        await page.FillAsync("#password", DemoEndpoints.KeycloakPassword);
        await page.ClickAsync("#kc-login");

        // After the code exchange we end up back on the BFF.
        await page.WaitForURLAsync(
            url => url.StartsWith(DemoEndpoints.BffKeycloak, StringComparison.Ordinal),
            new PageWaitForURLOptions { Timeout = 30_000 });

        // The session cookie is now set; /bff/user must return the authenticated identity.
        var response = await page.GotoAsync($"{DemoEndpoints.BffKeycloak}/bff/user");
        Assert.NotNull(response);
        Assert.Equal(200, response!.Status);

        var body = await response.TextAsync();
        Assert.Contains("\"authenticated\":true", body);
        Assert.Contains(DemoEndpoints.KeycloakUser, body);
    }

    [Fact]
    public async Task Logged_in_user_token_is_forwarded_to_the_backend()
    {
        await using var context = await fixture.Browser.NewContextAsync(
            new BrowserNewContextOptions { IgnoreHTTPSErrors = true });
        var page = await context.NewPageAsync();

        await page.GotoAsync($"{DemoEndpoints.BffKeycloak}/bff/login");
        await page.FillAsync("#username", DemoEndpoints.KeycloakUser);
        await page.FillAsync("#password", DemoEndpoints.KeycloakPassword);
        await page.ClickAsync("#kc-login");
        await page.WaitForURLAsync(
            url => url.StartsWith(DemoEndpoints.BffKeycloak, StringComparison.Ordinal),
            new PageWaitForURLOptions { Timeout = 30_000 });

        // /api/me forwards the user's access token to the backend via BackendAuthPolicies.BearerToken.
        var response = await page.GotoAsync($"{DemoEndpoints.BffKeycloak}/api/me");
        Assert.NotNull(response);
        Assert.Equal(200, response!.Status);

        var body = await response.TextAsync();
        Assert.Contains("\"userTokenForwarded\":true", body);
    }
}
