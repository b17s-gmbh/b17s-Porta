using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Net.Mime;
using System.Text;

using b17s.Porta.Configuration;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Integration;

/// <summary>
/// Suite 2 of the E2E plan: backend authentication folding. Drives the BFF as a black box
/// over <see cref="PortaTestHost"/> with TestServer-hosted <see cref="FakeIdp"/> and
/// <see cref="FakeBackend"/>, asserting on BOTH Porta's response AND what the backend actually
/// received (the forwarded credential). Covers the BearerToken / TokenExchange / BasicAuth / None
/// policies and the opt-in refresh-on-401 retry.
/// </summary>
public sealed class BackendAuthE2ETests
{
    private const string BackendBase = "http://backend.test";

    [Fact]
    public async Task BearerToken_ForwardsAccessToken()
    {
        // After OIDC login, a BearerToken-policy endpoint must forward the session's access token
        // as `Authorization: Bearer <jwt>`. Assert the backend saw a real session JWT (aud "api",
        // sub "user-1") - not an empty or fabricated credential.
        using var idp = new FakeIdp();
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

        var recorded = Assert.Single(backend.ReceivedRequests);
        var bearer = AssertBearer(recorded.Authorization);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(bearer);
        Assert.Contains("api", jwt.Audiences);
        Assert.Equal("user-1", jwt.Claims.First(c => c.Type == "sub").Value);
    }

    [Fact]
    public async Task BearerToken_AnonymousCaller_ReturnsAuthFailure()
    {
        // The documented failure mode: an unauthenticated caller is rejected by authorization
        // BEFORE the transformer runs, so the backend never sees a (missing) token. The exact
        // status is a challenge (401/302 depending on scheme); the security-relevant invariant
        // is that nothing reached the backend.
        using var idp = new FakeIdp();
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

        // No login: a bare client carries no session cookie.
        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/api/data", TestContext.Current.CancellationToken);

        Assert.False(response.IsSuccessStatusCode);
        Assert.Empty(backend.ReceivedRequests);
    }

    [Fact]
    public async Task TokenExchange_FetchesAudienceSpecificToken()
    {
        // With the TokenExchange policy the backend must receive the EXCHANGED token (RFC 8693),
        // scoped to the requested audience - not the original session access token. The fake IdP
        // mints exchange tokens carrying aud=<audience> and purpose=token-exchange.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/orders", WriteOk);

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<BackendPayload>()
                .FromGet("/api/orders")
                .ToBackend("GET", $"{BackendBase}/orders")
                .WithTokenExchange("orders-api")
                .RequireAuth()
                .Build())
            .StartAsync();

        var client = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        var response = await client.GetAsync("/api/orders", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var recorded = Assert.Single(backend.ReceivedRequests);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(AssertBearer(recorded.Authorization));
        Assert.Contains("orders-api", jwt.Audiences);
        Assert.Equal("token-exchange", jwt.Claims.First(c => c.Type == "purpose").Value);
        Assert.Equal(1, idp.ExchangeCallCountFor("orders-api"));
    }

    [Fact]
    public async Task TokenExchange_CachesPerAudience()
    {
        // Two consecutive requests for the same audience within one session must hit the API-token
        // cache: the IdP exchange endpoint is called exactly once, not once per request.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/orders", WriteOk);

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .WithSession()
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<BackendPayload>()
                .FromGet("/api/orders")
                .ToBackend("GET", $"{BackendBase}/orders")
                .WithTokenExchange("orders-api")
                .RequireAuth()
                .Build())
            .StartAsync();

        // The exchanged-token cache lives in HttpContext.Session, so the session cookie must
        // round-trip between the two calls - hence the cookie-jar client.
        var client = await bff.LoginWithCookieJarAsync(idp, TestContext.Current.CancellationToken);
        (await client.GetAsync("/api/orders", TestContext.Current.CancellationToken)).EnsureSuccessStatusCode();
        (await client.GetAsync("/api/orders", TestContext.Current.CancellationToken)).EnsureSuccessStatusCode();

        Assert.Equal(2, backend.ReceivedRequests.Count);
        Assert.Equal(1, idp.ExchangeCallCount);
    }

    [Fact]
    public async Task BasicAuth_ForwardsBasicCredentials()
    {
        // Config-provided Basic credentials must appear as `Authorization: Basic base64(user:pass)`.
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", WriteOk);

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .ConfigureServices(services => services.Configure<BackendServiceOptions>(options =>
            {
                options.BasicAuth.Username = "svc-user";
                options.BasicAuth.Password = "svc-secret";
            }))
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<BackendPayload>()
                .FromGet("/api/data")
                .ToBackend("GET", $"{BackendBase}/data")
                .WithBackendAuth(BackendAuthPolicies.BasicAuth)
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var response = await bff.CreateAuthenticatedClient()
            .GetAsync("/api/data", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var recorded = Assert.Single(backend.ReceivedRequests);
        var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("svc-user:svc-secret"));
        Assert.Equal(expected, recorded.Authorization);
    }

    [Fact]
    public async Task Anonymous_StripsIncomingAuthHeader()
    {
        // A None-policy endpoint must not leak the caller's inbound Authorization header to the
        // backend - the BFF builds a fresh outbound request and applies no credential.
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", WriteOk);

        using var bff = await new PortaTestHost()
            .WithBackend(backend)
            .MapEndpoints(endpoints => endpoints
                .MapPassThrough<BackendPayload>()
                .FromGet("/api/data")
                .ToBackend("GET", $"{BackendBase}/data")
                .AllowAnonymous()
                .Build())
            .StartAsync();

        var client = bff.CreateAuthenticatedClient();
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/data");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer caller-supplied-token");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var recorded = Assert.Single(backend.ReceivedRequests);
        Assert.Null(recorded.Authorization);
    }

    [Fact]
    public async Task BackendReturns401_ProvokesTokenRefresh_ThenRetries()
    {
        // Opt-in refresh-on-401: the first backend call gets the stale token and is rejected; the
        // BFF force-refreshes the session token and retries; the second call carries the ROTATED
        // token and succeeds. Two backend calls total, with distinct Authorization headers.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        var calls = 0;
        backend.MapGet("/data", async ctx =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
            await WriteOk(ctx);
        });

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

        Assert.Equal(2, backend.ReceivedRequests.Count);
        var firstToken = AssertBearer(backend.ReceivedRequests[0].Authorization);
        var secondToken = AssertBearer(backend.ReceivedRequests[1].Authorization);
        Assert.NotEqual(firstToken, secondToken);
    }

    [Fact]
    public async Task BackendReturns401_AfterRefresh_FailsHard()
    {
        // When the backend keeps returning 401 even after the refresh, the BFF must give up after a
        // single retry (no infinite loop) and surface the failure. A pass-through error mapper makes
        // the backend 401 visible to the caller as 401.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        });

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .ConfigureServices(services =>
                services.AddSingleton<IBackendErrorMapper, PassThroughBackendErrorMapper>())
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

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        // Exactly one original attempt + one refresh-retry. No retry loop.
        Assert.Equal(2, backend.ReceivedRequests.Count);
    }

    [Fact]
    public async Task Aggregator_WithUserToken_ForwardsAccessTokenToNamedBackend()
    {
        // Regression: aggregated/named backends must forward the user's session token. Before the
        // fix, NamedBackendEndpoint.ToBackendRequest() never set AccessToken, so .WithUserToken()
        // backends were called with no Authorization header at all.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", WriteOk);

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .ConfigureCore(opts => opts.TrustedHosts = [BackendBase])
            .ConfigureServices(s => s.AddTransformer<ProbeAggregator>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<ProbeAggregator, ProbeResult>()
                .FromGet("/api/agg")
                .ToBackends(("Data", "GET", $"{BackendBase}/data").WithUserToken())
                .RequireAuth()
                .Build())
            .StartAsync();

        var client = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        var response = await client.GetAsync("/api/agg", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var recorded = Assert.Single(backend.ReceivedRequests);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(AssertBearer(recorded.Authorization));
        Assert.Equal("user-1", jwt.Claims.First(c => c.Type == "sub").Value);
    }

    [Fact]
    public async Task Aggregator_BearerTokenPolicy_ForwardsAccessTokenToNamedBackend()
    {
        // Same regression via the explicit .WithAuth(BearerToken) policy (no trusted-host gate),
        // mirroring single-backend BearerToken semantics.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", WriteOk);

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .ConfigureServices(s => s.AddTransformer<ProbeAggregator>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<ProbeAggregator, ProbeResult>()
                .FromGet("/api/agg")
                .ToBackends(("Data", "GET", $"{BackendBase}/data").WithAuth(BackendAuthPolicies.BearerToken))
                .RequireAuth()
                .Build())
            .StartAsync();

        var client = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        var response = await client.GetAsync("/api/agg", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var recorded = Assert.Single(backend.ReceivedRequests);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(AssertBearer(recorded.Authorization));
        Assert.Equal("user-1", jwt.Claims.First(c => c.Type == "sub").Value);
    }

    [Fact]
    public async Task Aggregation_BackendReturns401_RefreshesOnceAndRetriesBothLegs()
    {
        // Two user-token legs both 401 on their first call. The parallel fan-out must collapse to a
        // SINGLE IdP refresh (gate + in-memory dedup), then each leg retries once with the rotated
        // token and succeeds. Default-on: no .WithRefreshOn401() needed.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/a", FailFirstThenOk());
        backend.MapGet("/b", FailFirstThenOk());

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .ConfigureServices(s => s.AddTransformer<TwoBackendAggregator>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<TwoBackendAggregator, TwoValues>()
                .FromGet("/api/agg")
                .ToBackends(
                    ("A", "GET", $"{BackendBase}/a").WithAuth(BackendAuthPolicies.BearerToken),
                    ("B", "GET", $"{BackendBase}/b").WithAuth(BackendAuthPolicies.BearerToken))
                .RequireAuth()
                .Build())
            .StartAsync();

        var client = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        var response = await client.GetAsync("/api/agg", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<TwoValues>(TestContext.Current.CancellationToken);
        Assert.Equal("ok", body!.A);
        Assert.Equal("ok", body.B);
        Assert.Equal(1, idp.RefreshGrantCount);
        Assert.Equal(2, backend.ReceivedRequests.Count(r => r.Path == "/a"));
        Assert.Equal(2, backend.ReceivedRequests.Count(r => r.Path == "/b"));
    }

    [Fact]
    public async Task Aggregation_MixedPolicies_OnlyUserTokenLegRefreshes()
    {
        // One BearerToken leg (401 -> refresh -> 200) plus one BasicAuth leg that stays 401. The
        // BasicAuth 401 must NOT trigger a refresh (refreshing the user token can't fix Basic creds),
        // so it is not retried; only the user-token leg refreshes.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/a", FailFirstThenOk());
        backend.MapGet("/b", ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        });

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .ConfigureServices(s => s.AddTransformer<TwoBackendAggregator>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<TwoBackendAggregator, TwoValues>()
                .FromGet("/api/agg")
                .ToBackends(
                    ("A", "GET", $"{BackendBase}/a").WithAuth(BackendAuthPolicies.BearerToken),
                    ("B", "GET", $"{BackendBase}/b").WithAuth(BackendAuthPolicies.BasicAuth))
                .RequireAuth()
                .Build())
            .StartAsync();

        var client = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        var response = await client.GetAsync("/api/agg", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<TwoValues>(TestContext.Current.CancellationToken);
        Assert.Equal("ok", body!.A);
        Assert.Null(body.B);
        Assert.Equal(1, idp.RefreshGrantCount);
        Assert.Equal(2, backend.ReceivedRequests.Count(r => r.Path == "/a"));
        Assert.Equal(1, backend.ReceivedRequests.Count(r => r.Path == "/b"));
    }

    [Fact]
    public async Task Aggregation_RefreshFails_SkipsRetry_NoStorm()
    {
        // When the IdP refresh fails (no rotation), the legs must NOT retry - one refresh attempt
        // total (deduped across legs), each backend hit exactly once, no loop.
        using var idp = new FakeIdp { FailRefreshGrant = true };
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/a", ctx => { ctx.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; });
        backend.MapGet("/b", ctx => { ctx.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; });

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .ConfigureServices(s => s.AddTransformer<TwoBackendAggregator>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<TwoBackendAggregator, TwoValues>()
                .FromGet("/api/agg")
                .ToBackends(
                    ("A", "GET", $"{BackendBase}/a").WithAuth(BackendAuthPolicies.BearerToken),
                    ("B", "GET", $"{BackendBase}/b").WithAuth(BackendAuthPolicies.BearerToken))
                .RequireAuth()
                .Build())
            .StartAsync();

        var client = await bff.LoginAsync(idp, TestContext.Current.CancellationToken);
        var response = await client.GetAsync("/api/agg", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<TwoValues>(TestContext.Current.CancellationToken);
        Assert.Null(body!.A);
        Assert.Null(body.B);
        Assert.Equal(1, idp.RefreshGrantCount);
        Assert.Equal(1, backend.ReceivedRequests.Count(r => r.Path == "/a"));
        Assert.Equal(1, backend.ReceivedRequests.Count(r => r.Path == "/b"));
    }

    [Fact]
    public async Task RefreshOn401_DisabledViaConfig_PropagatesUnchanged()
    {
        // The global opt-out (PortaCore:RefreshBackendTokenOn401 = false) disables the behavior:
        // a backend 401 is surfaced with no refresh and no retry.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        });

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .ConfigureCore(opts => opts.RefreshBackendTokenOn401 = false)
            .ConfigureServices(services =>
                services.AddSingleton<IBackendErrorMapper, PassThroughBackendErrorMapper>())
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

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(backend.ReceivedRequests);
        Assert.Equal(0, idp.RefreshGrantCount);
    }

    [Fact]
    public async Task Aggregation_ParallelTokenExchange_CachesBothAudiences()
    {
        // Two TokenExchange legs to different audiences exchange in parallel. The api-token cache is a
        // read-modify-write of one HttpContext.Session entry; without serialized merge-on-write the
        // legs would clobber each other and one audience would be lost (re-exchanged next request).
        // Asserting exactly one exchange per audience across two rounds proves both were cached.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/a", WriteOk);
        backend.MapGet("/b", WriteOk);

        using var bff = await new PortaTestHost()
            .WithFakeIdp(idp)
            .WithBackend(backend)
            .WithAuthorization()
            .WithSession()
            .ConfigureServices(s => s.AddTransformer<TwoBackendAggregator>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<TwoBackendAggregator, TwoValues>()
                .FromGet("/api/agg")
                .ToBackends(
                    ("A", "GET", $"{BackendBase}/a").WithTokenExchange("aud-a"),
                    ("B", "GET", $"{BackendBase}/b").WithTokenExchange("aud-b"))
                .RequireAuth()
                .Build())
            .StartAsync();

        // Cookie-jar client so the session (holding the exchanged-token cache) round-trips.
        var client = await bff.LoginWithCookieJarAsync(idp, TestContext.Current.CancellationToken);
        (await client.GetAsync("/api/agg", TestContext.Current.CancellationToken)).EnsureSuccessStatusCode();
        (await client.GetAsync("/api/agg", TestContext.Current.CancellationToken)).EnsureSuccessStatusCode();

        Assert.Equal(2, idp.ExchangeCallCount);
        Assert.Equal(1, idp.ExchangeCallCountFor("aud-a"));
        Assert.Equal(1, idp.ExchangeCallCountFor("aud-b"));
    }

    // Backend handler that returns 401 on its first call and 200 (BackendPayload) thereafter.
    private static RequestDelegate FailFirstThenOk()
    {
        var calls = 0;
        return async ctx =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
            await WriteOk(ctx);
        };
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

    private sealed class BackendPayload
    {
        public string Value { get; set; } = string.Empty;
    }

    private sealed class ProbeAggregator : AggregatingTransformer<ProbeResult>
    {
        protected override void Configure(AggregatorBuilder builder)
            => builder.Backend<BackendPayload>("Data");

        protected override ProbeResult MapResults(AggregatorResults results, TransformerContext context)
            => new() { Value = results.Get<BackendPayload>("Data")?.Value };
    }

    private sealed class ProbeResult
    {
        public string? Value { get; set; }
    }

    private sealed class TwoBackendAggregator : AggregatingTransformer<TwoValues>
    {
        protected override void Configure(AggregatorBuilder builder)
        {
            builder.Backend<BackendPayload>("A");
            builder.Backend<BackendPayload>("B");
        }

        protected override TwoValues MapResults(AggregatorResults results, TransformerContext context)
            => new()
            {
                A = results.Get<BackendPayload>("A")?.Value,
                B = results.Get<BackendPayload>("B")?.Value,
            };
    }

    private sealed class TwoValues
    {
        public string? A { get; set; }
        public string? B { get; set; }
    }
}
