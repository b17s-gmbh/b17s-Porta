using System.Net;

using Xunit;

namespace Demo.E2E.Tests;

/// <summary>
/// Fast, browser-free functional checks: the providers are discoverable, public pass-through
/// works without auth, and protected APIs are actually protected.
/// </summary>
[Collection(DemoCollection.Name)]
public sealed class SmokeTests(AppHostFixture fixture)
{
    [Fact]
    public async Task Keycloak_discovery_document_is_reachable()
    {
        var ct = TestContext.Current.CancellationToken;
        var json = await fixture.Http.GetStringAsync(DemoEndpoints.KeycloakDiscovery, ct);
        Assert.Contains("\"issuer\"", json);
        Assert.Contains("/realms/porta-demo", json);
    }

    [Fact]
    public async Task Zitadel_discovery_document_is_reachable()
    {
        var ct = TestContext.Current.CancellationToken;
        var json = await fixture.Http.GetStringAsync(DemoEndpoints.ZitadelDiscovery, ct);
        Assert.Contains("\"issuer\"", json);
    }

    [Theory]
    [InlineData(DemoEndpoints.BffKeycloak)]
    [InlineData(DemoEndpoints.BffZitadel)]
    public async Task Public_passthrough_returns_backend_data_without_auth(string bff)
    {
        var ct = TestContext.Current.CancellationToken;
        using var resp = await fixture.Http.GetAsync($"{bff}/api/weather", ct);
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync(ct);
        Assert.Contains("temperature", body, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(DemoEndpoints.BffKeycloak)]
    [InlineData(DemoEndpoints.BffZitadel)]
    public async Task Protected_api_is_denied_when_unauthenticated(string bff)
    {
        var ct = TestContext.Current.CancellationToken;
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

        using var resp = await client.GetAsync($"{bff}/api/me", ct);

        // Access must be blocked — either a 401 (BFF API style) or a challenge redirect to the IdP.
        Assert.True(
            resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Found or HttpStatusCode.Redirect,
            $"Expected the protected API to deny anonymous access, got {(int)resp.StatusCode}.");
    }
}
