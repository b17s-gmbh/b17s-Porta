using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Net.Mime;
using System.Security.Claims;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Integration;

/// <summary>
/// Suite 3 of the E2E plan: the session lifecycle. Drives the BFF as a black box over
/// <see cref="PortaTestHost"/> with a TestServer-hosted <see cref="FakeIdp"/> (and, where a
/// downstream call is needed, <see cref="FakeBackend"/>), asserting on BOTH Porta's response AND
/// the IdP-observed side effects (refresh-grant calls, token revocations). Covers proactive
/// access-token refresh, front-channel logout + revocation, IdP-initiated back-channel logout,
/// the session admin endpoints, and concurrent-refresh de-duplication via <c>RefreshLockRegistry</c>.
/// </summary>
/// <remarks>
/// Complements <see cref="OidcEndToEndTests"/> (which owns the P1-7 login-flow regression coverage)
/// rather than replacing it.
/// </remarks>
public sealed class SessionLifecycleE2ETests
{
    private const string BackendBase = "http://backend.test";

    [Fact]
    public async Task LoggedInRequest_AfterTokenExpiry_RefreshesAccessToken()
    {
        // The IdP issues a 1-second initial access token, so the cookie ticket's expires_at lands
        // inside Porta's 60s refresh skew. The next authenticated request must proactively refresh
        // against the IdP (one refresh_token grant) and forward the ROTATED token to the backend.
        using var idp = new FakeIdp { InitialAccessTokenExpiresInSeconds = 1 };
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", WriteOk);

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<BackendPayload>()
                .FromGet("/api/data")
                .ToBackend("GET", $"{BackendBase}/data")
                .WithBackendAuth(BackendAuthPolicies.BearerToken)
                .RequireAuth()
                .Build())
            .StartAsync();

        var client = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        var response = await client.GetAsync("/api/data", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        // Exactly one proactive refresh (the auth context is resolved once per request).
        Assert.Equal(1, idp.RefreshGrantCount);

        // The backend saw a real, rotated session JWT - not the stale one and not a fabricated token.
        var recorded = Assert.Single(backend.ReceivedRequests);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(AssertBearer(recorded.Authorization));
        Assert.Contains("api", jwt.Audiences);
        Assert.Equal("user-1", jwt.Claims.First(c => c.Type == "sub").Value);
    }

    [Fact]
    public async Task Logout_ClearsCookie_RevokesRefreshToken_AndEndsSession()
    {
        // POST /bff/logout (global, browser flow): redirect to the IdP end-session endpoint, clear the
        // auth cookie, revoke the refresh token at the IdP, and tear down the server-side ticket so
        // the now-stale cookie no longer authenticates.
        using var idp = new FakeIdp();
        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            // The login client has no antiforgery token; logout's CSRF guard is covered elsewhere.
            .ConfigureOidcLogout(options => options.RequireAntiforgery = false)
            .MapEndpoints(MapWhoAmI)
            .StartAsync();

        var client = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/whoami", TestContext.Current.CancellationToken)).StatusCode);

        var logout = await client.PostAsync("/bff/logout", content: null, TestContext.Current.CancellationToken);

        // Global logout 302s to the IdP's end-session endpoint.
        Assert.Equal(HttpStatusCode.Redirect, logout.StatusCode);
        Assert.Equal("/end-session", logout.Headers.Location!.AbsolutePath);

        // The auth cookie is deleted (epoch expiry) and the IdP recorded a refresh-token revocation.
        Assert.Contains(
            SetCookieHeaders(logout),
            c => c.StartsWith("__Porta=", StringComparison.Ordinal)
                && c.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
        Assert.True(idp.RevocationCount >= 1);

        // The session is gone server-side: the stale cookie no longer authenticates.
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/whoami", TestContext.Current.CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task BackChannelLogout_TerminatesSessionAcrossReplicas()
    {
        // An IdP-initiated, signed logout_token terminates the matching session out-of-band. After
        // it lands, the original session's cookie is dead - exactly the "logout propagates across
        // replicas" guarantee (here the same in-memory store stands in for the shared one).
        using var idp = new FakeIdp();
        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackChannelLogout()
            .MapEndpoints(MapWhoAmI)
            .StartAsync();

        var client = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/whoami", TestContext.Current.CancellationToken)).StatusCode);

        var logoutToken = idp.CreateBackChannelLogoutToken(sub: "user-1");
        var form = new FormUrlEncodedContent([new KeyValuePair<string, string>("logout_token", logoutToken)]);
        var backChannel = await bff.CreateAuthenticatedClient()
            .PostAsync("/bff/backchannel-logout", form, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, backChannel.StatusCode);

        // A subsequent request from the same session is now unauthenticated.
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await client.GetAsync("/api/whoami", TestContext.Current.CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task SessionAdmin_ListSessions_RequiresPolicyAuth()
    {
        // GET /bff/admin/sessions enforces the admin policy: anonymous = 401, authenticated-but-not-
        // admin = 403, and a caller satisfying the policy gets the JSON session list.
        using var idp = new FakeIdp();
        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithSessionAdmin("SessionAdmin")
            .StartAsync();

        // Anonymous caller -> 401.
        var anonymous = await bff.CreateAuthenticatedClient()
            .GetAsync("/bff/admin/sessions?email=user@example.com", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        // Authenticated non-admin (default identity carries no porta_admin claim) -> 403.
        idp.NextUserIdentity = MakeIdentity(sub: "user-1", email: "user@example.com", isAdmin: false);
        var userClient = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        var forbidden = await userClient.GetAsync("/bff/admin/sessions?email=user@example.com", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        // Admin caller -> 200 with the session list for the queried email.
        idp.NextUserIdentity = MakeIdentity(sub: "admin-1", email: "admin@example.com", isAdmin: true);
        var adminClient = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        var ok = await adminClient.GetAsync("/bff/admin/sessions?email=admin@example.com", TestContext.Current.CancellationToken);
        ok.EnsureSuccessStatusCode();

        var list = await ok.Content.ReadFromJsonAsync<AdminSessionList>(TestContext.Current.CancellationToken);
        Assert.NotNull(list);
        Assert.True(list!.SessionCount >= 1);
        Assert.Contains(list.Sessions, s => s.UserId == "admin-1");
    }

    [Fact]
    public async Task SessionAdmin_TerminateSession_RevokesRefreshToken()
    {
        // DELETE /bff/admin/sessions/{id}?revokeTokens=true terminates the session AND revokes its
        // refresh token at the IdP. We act on the admin's own session (admin == target keeps the test
        // self-contained) and prove both the IdP revocation and the server-side teardown.
        using var idp = new FakeIdp();
        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            // Admin DELETE from a cookie-authenticated caller would otherwise need an antiforgery token.
            .WithSessionAdmin("SessionAdmin", options => options.RequireAntiforgery = false)
            .MapEndpoints(MapWhoAmI)
            .StartAsync();

        idp.NextUserIdentity = MakeIdentity(sub: "admin-1", email: "admin@example.com", isAdmin: true);
        var admin = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);

        var listResponse = await admin.GetAsync("/bff/admin/sessions?email=admin@example.com", TestContext.Current.CancellationToken);
        listResponse.EnsureSuccessStatusCode();
        var list = await listResponse.Content.ReadFromJsonAsync<AdminSessionList>(TestContext.Current.CancellationToken);
        var sessionId = Assert.Single(list!.Sessions).SessionId;

        var delete = await admin.DeleteAsync(
            $"/bff/admin/sessions/{sessionId}?revokeTokens=true", TestContext.Current.CancellationToken);
        delete.EnsureSuccessStatusCode();

        // The IdP saw the RFC 7009 revocation, and the terminated session no longer authenticates.
        Assert.True(idp.RevocationCount >= 1);
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await admin.GetAsync("/api/whoami", TestContext.Current.CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task ConcurrentRequests_ShareSingleRefresh()
    {
        // Two simultaneous requests arrive with an expired (1s) token. RefreshLockRegistry must
        // serialize the refresh so the IdP sees exactly one refresh_token grant - not one per request
        // - while both requests still succeed and the session is left with a single valid rotated token.
        using var idp = new FakeIdp { InitialAccessTokenExpiresInSeconds = 1 };
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", WriteOk);

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<BackendPayload>()
                .FromGet("/api/data")
                .ToBackend("GET", $"{BackendBase}/data")
                .WithBackendAuth(BackendAuthPolicies.BearerToken)
                .RequireAuth()
                .Build())
            .StartAsync();

        var client = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);

        var first = client.GetAsync("/api/data", TestContext.Current.CancellationToken);
        var second = client.GetAsync("/api/data", TestContext.Current.CancellationToken);
        var responses = await Task.WhenAll(first, second);

        Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));

        // Exactly one IdP refresh across both concurrent requests.
        Assert.Equal(1, idp.RefreshGrantCount);

        // The session is uncorrupted: a follow-up request still works on the rotated token without
        // a further refresh (the rotated token is far from expiry).
        var followUp = await client.GetAsync("/api/data", TestContext.Current.CancellationToken);
        followUp.EnsureSuccessStatusCode();
        Assert.Equal(1, idp.RefreshGrantCount);
    }

    private static void MapWhoAmI(IEndpointRouteBuilder endpoints) =>
        endpoints.MapGet("/api/whoami", (HttpContext ctx) =>
            ctx.User.Identity?.IsAuthenticated == true
                ? Results.Ok(new WhoAmI(ctx.User.FindFirst("sub")?.Value
                    ?? ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value))
                : Results.Unauthorized());

    private static ClaimsIdentity MakeIdentity(string sub, string email, bool isAdmin)
    {
        var identity = new ClaimsIdentity(authenticationType: "fake-idp");
        identity.AddClaim(new Claim("sub", sub));
        identity.AddClaim(new Claim("email", email));
        identity.AddClaim(new Claim("email_verified", "true", ClaimValueTypes.Boolean));
        identity.AddClaim(new Claim("name", "Test User"));
        if (isAdmin)
        {
            // The admin policy registered by WithSessionAdmin is satisfied by this claim.
            identity.AddClaim(new Claim("porta_admin", "true"));
        }
        return identity;
    }

    private static async Task WriteOk(HttpContext ctx)
    {
        ctx.Response.ContentType = MediaTypeNames.Application.Json;
        await ctx.Response.WriteAsJsonAsync(new BackendPayload { Value = "ok" });
    }

    private static string AssertBearer(string? authorizationHeader)
    {
        Assert.NotNull(authorizationHeader);
        Assert.StartsWith("Bearer ", authorizationHeader);
        return authorizationHeader["Bearer ".Length..];
    }

    private static IEnumerable<string> SetCookieHeaders(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values) ? values : [];

    private sealed class BackendPayload
    {
        public string Value { get; set; } = string.Empty;
    }

    private sealed record WhoAmI(string? Sub);

    private sealed record AdminSessionList(string Email, int SessionCount, List<AdminSession> Sessions);

    private sealed record AdminSession(string SessionId, string UserId);
}
