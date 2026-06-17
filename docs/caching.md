# Response Caching

Porta does **not** model response caching itself, and nothing is cached by default. It doesn't
need to: a Porta endpoint's `.Build()` returns a stock `RouteHandlerBuilder`, so ASP.NET Core's
[output caching](https://learn.microsoft.com/aspnet/core/performance/caching/output) middleware
composes straight onto it. That gives you a battle-tested, HA-capable cache without Porta
reimplementing one.

This guide covers the supported approach:

1. **[Whole-response output caching](#whole-response-output-caching)** — cache an entire endpoint's
   response with the framework's `OutputCache`. This is the recommended path and the focus of this
   guide.
2. **[Distributed (HA) caching](#distributed-ha-caching)** — back the cache with Redis so the cache
   is shared across replicas instead of per-instance.
3. **[Caching only part of an aggregation](#caching-only-part-of-an-aggregation)** — when one leg of
   a multi-backend endpoint is cacheable but the rest isn't, cache that leg *inside* the transformer.

> **The one rule that matters:** never cache a response that varies by user unless the cache key
> varies by user too. A BFF forwards tokens and returns per-identity data; a misconfigured cache
> serves one user's response to another. The default output-cache policy keys on the URL only — it
> does **not** vary by the auth cookie. See [Caching and authentication](#caching-and-authentication).

## Whole-response output caching

Output caching is opt-in middleware. Register it, add it to the pipeline, then attach a policy to
the endpoints you want cached.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPortaCore();
builder.Services.AddOutputCache();          // 1. register the cache + default policy

var app = builder.Build();

app.UseOutputCache();                         // 2. add the middleware (before endpoints)

app.MapPassThrough<ProductsResponse>()
    .FromGet("/api/products")
    .ToGet("https://products.internal/products")
    .AllowAnonymous()
    .Build()                                  // 3. RouteHandlerBuilder from here on
    .CacheOutput(p => p.Expire(TimeSpan.FromSeconds(30)));

app.Run();
```

`UseOutputCache()` must sit before the endpoint execution in the pipeline. When you also use
authentication/authorization, place it after `UseAuthentication()`/`UseAuthorization()` so the
auth state is resolved before the cache decides whether to serve — relevant if you ever build an
auth-varying policy (see below).

A few framework defaults worth knowing:

- The built-in policy only caches `GET`/`HEAD` requests that return `200`, and only when the
  response sets no cookies and the request carries no `Authorization` **header**.
- The cache key is the request path plus query string. Use `.SetVaryByQuery(...)` to restrict which
  query parameters vary the cache, or `.SetVaryByHeader(...)` to add headers.
- `.Expire(...)` is the absolute TTL. There is no sliding expiration in output caching by design.

### Tagging and invalidation

Tag endpoints so you can evict them as a group when the underlying data changes:

```csharp
app.MapPassThrough<ProductsResponse>()
    .FromGet("/api/products")
    .ToGet("https://products.internal/products")
    .AllowAnonymous()
    .Build()
    .CacheOutput(p => p.Expire(TimeSpan.FromMinutes(5)).Tag("catalog"));
```

```csharp
// e.g. from a webhook the backend calls when the catalog changes:
app.MapPost("/internal/invalidate/catalog",
    async (IOutputCacheStore cache, CancellationToken ct) =>
    {
        await cache.EvictByTagAsync("catalog", ct);
        return Results.NoContent();
    })
    .RequireAuthorization("internal");        // protect the invalidation hook
```

### A reusable cache policy

If several endpoints share caching rules, register a named policy once and reference it by name —
keeps the cache contract in one place instead of scattered `.CacheOutput(p => ...)` lambdas:

```csharp
builder.Services.AddOutputCache(options =>
{
    options.AddPolicy("short-public", p =>
        p.Expire(TimeSpan.FromSeconds(30)).Tag("public"));
});

// ...
    .Build()
    .CacheOutput("short-public");
```

## Distributed (HA) caching

The default `OutputCache` store is **in-memory and per-replica**. Behind a load balancer with
multiple replicas that means each instance caches independently: lower hit rates, and a `Tag`
eviction on one replica doesn't clear the others. For a shared cache, register a distributed
`IOutputCacheStore`:

```csharp
builder.Services.AddOutputCache();
builder.Services.AddStackExchangeRedisOutputCache(opts =>
{
    opts.Configuration = builder.Configuration["Redis:ConnectionString"];
});
```

This is the same Redis you likely already run for the auth ticket/session store (see
[HA Deployment](ha-deployment.md)), but note it is a **distinct registration**: the output-cache
store is an `IOutputCacheStore`, separate from the `IDistributedCache` used for sessions. Registering
one does not register the other. You can point both at the same Redis instance; keep their key
namespaces from colliding (the output-cache store uses its own prefix, so they don't by default).

With a distributed store, `EvictByTagAsync` clears the entry for every replica, and a response
cached by replica A is served by replica B. No sticky sessions required — consistent with the rest
of Porta's [HA model](ha-deployment.md).

## Caching and authentication

This is where a BFF differs from a plain API, and where output caching is easy to get dangerously
wrong.

**Safe to cache:** endpoints marked `.AllowAnonymous()` that forward no user token and return the
same bytes to everyone — public catalogs, config, reference data, anonymous search. These are the
endpoints output caching is *for*.

**Not safe to cache as-is:** anything that forwards the user's token
(`BackendAuthPolicies.BearerToken`, token exchange) or returns per-identity data. The default policy
keys on the URL only. Critically, **it does not vary by the auth cookie** — so applying a default
`.CacheOutput()` to a cookie-authenticated endpoint will serve the first user's cached response to
every subsequent user. The `Authorization`-header guard in the default policy does **not** protect
you here, because Porta sessions authenticate via cookie, not that header.

If you must cache a user-varying response, partition the key by the user explicitly:

```csharp
builder.Services.AddOutputCache(options =>
{
    options.AddPolicy("per-user", p => p
        .Expire(TimeSpan.FromSeconds(15))
        // vary the cache by the authenticated subject so users never share an entry
        .VaryByValue(ctx =>
            new KeyValuePair<string, string>(
                "sub", ctx.User.FindFirst("sub")?.Value ?? "anonymous")));
});

// ...
    .RequireAuth()
    .WithBackendAuth(BackendAuthPolicies.BearerToken)
    .Build()
    .CacheOutput("per-user");
```

Even then, weigh whether it's worth it: per-user entries have low hit rates, store user data in a
shared cache, and can outlive a logout or a permission change for the duration of the TTL. Keep TTLs
short, and prefer caching anonymous shared reads over per-user responses. When in doubt, don't cache.

## Caching only part of an aggregation

Output caching caches the *whole* merged response — it can't cache one leg of an
[aggregating transformer](transformers.md#level-3-multi-backend-aggregation) while leaving the others
live. When exactly one backend is slow-but-cacheable (e.g. a shared reference feed) and the rest are
per-user, cache that single call *inside* the transformer instead of caching the endpoint.

### Declarative: `WithCache(...)` on the aggregation builder

Use the `WithCache(...)` modifier on a backend leg in the aggregator's `Configure`. It caches that
one leg's deserialized result in [`HybridCache`](https://learn.microsoft.com/aspnet/core/performance/caching/hybrid)
— in-process (L1) speed, an optional distributed (L2) backing store for HA, and stampede protection
(concurrent cold requests collapse to a single backend call). Register the cache once during startup;
Porta does not pick a backend for you:

```csharp
builder.Services.AddHybridCache();                  // L1 only
builder.Services.AddStackExchangeRedisCache(o =>     // add L2 → shared across replicas (HA)
    o.Configuration = builder.Configuration["Redis:ConnectionString"]);
```

```csharp
public sealed class DashboardTransformer : AggregatingTransformer<DashboardResponse>
{
    protected override void Configure(AggregatorBuilder builder)
    {
        // Shared, anonymous leg — cached across all users for 5 minutes.
        builder.Backend<Weather>("Weather")
            .WithCache(TimeSpan.FromMinutes(5));

        // Per-user leg — never cached (no .WithCache() call); calls the backend on every request.
        builder.Backend<Profile>("Profile")
            .WithBody(ctx => new ProfileRequest { UserId = ctx.UserId! });

        // Per-user leg that IS cacheable, but MUST be partitioned by user.
        builder.Backend<Entitlements>("Entitlements")
            .WithCache(TimeSpan.FromSeconds(30), varyByUser: true);
    }

    protected override DashboardResponse MapResults(AggregatorResults results, TransformerContext context) =>
        new(results.Get<Profile>("Profile"),
            results.Get<Weather>("Weather"),
            results.Get<Entitlements>("Entitlements"));
}
```

What `WithCache(...)` does and the rules it enforces:

- **Key.** Keyed by the transformer, the leg name, the HTTP method, the **resolved** (route-interpolated)
  backend URL, and the request body when present — so different route/query values are different
  entries automatically. `varyByUser: true` partitions the key by the authenticated subject
  (`ctx.UserId`); `varyBy: ctx => ...` appends a custom dimension (tenant, locale, …).
- **Fail-closed safety.** A leg that forwards the user's identity (`BearerToken`, token exchange, or
  `WithUserToken()`) **must** set `varyByUser: true`. Caching such a leg with a shared key would serve
  one user's data to another, so Porta throws at request time instead. A `varyBy` key does **not**
  satisfy this — it's an extra dimension (tenant, locale) Porta can't inspect, so a `varyBy` that omits
  the user would silently re-open the leak; pair it *with* `varyByUser: true`, never in place of it. A
  `varyByUser` leg with no authenticated subject also throws — that signals an unauthenticated endpoint.
- **GET/HEAD only.** Caching a mutating verb is almost always a mistake, so `WithCache(...)` rejects
  any leg whose method is not `GET` or `HEAD`.
- **Never caches failures.** Only successful responses are stored. A `4xx`/`5xx`, a timeout, a thrown
  error, or a cancellation is returned to the caller uncached, so a transient failure can't poison the
  entry. A legitimate `200` with a null/empty body *is* a cacheable result.
- **TTL is the staleness bound.** A cached entitlement or permission can outlive a logout or a
  permission change for up to the TTL. Keep user-varying TTLs short — the same trade-off called out in
  [Caching and authentication](#caching-and-authentication).
- **Telemetry.** The per-leg `bff.backend` span is tagged `cache.enabled` and `cache.hit` so a
  served-from-cache leg is distinguishable from a backend round-trip. For ad-hoc debugging, set
  `PortaCore.VerboseCacheTelemetry = true` to additionally tag the span with `cache.key.hash` (the
  leg's hashed cache key). It's off by default because that key varies per route/body/user and would
  add high-cardinality noise to every span; turn it on temporarily, not in steady state.

If `.WithCache(...)` is used but no `HybridCache` is registered, the transformer throws — with a
message telling you to call `AddHybridCache()` — and never silently falls back to calling the backend
uncached. Porta also cross-checks every cacheable leg at **startup** (in `.Build()`): a user-varying
leg cached without a per-user key, a non-cacheable verb, or a missing `HybridCache` registration fails
the boot rather than waiting for the first request. (The request-time guard still runs as a back-stop;
if a transformer can't be constructed outside a request scope, the startup cross-check is skipped and
that guard takes over.)

### Tagging and invalidation

Attach `tags` to a cached leg, then evict the whole tagged group at once — e.g. from a webhook the
backend calls when the underlying data changes — by injecting `HybridCache` and calling
`RemoveByTagAsync`. This mirrors the [output-cache tag story](#tagging-and-invalidation) above, but for
a single aggregation leg:

```csharp
builder.Backend<Weather>("Weather")
    .WithCache(TimeSpan.FromMinutes(5), tags: ["weather", "reference-data"]);
```

```csharp
// e.g. from a webhook the weather backend calls when its data changes:
app.MapPost("/internal/invalidate/weather",
    async (HybridCache cache, CancellationToken ct) =>
    {
        await cache.RemoveByTagAsync("weather", ct);
        return Results.NoContent();
    })
    .RequireAuthorization("internal");        // protect the invalidation hook
```

As with output caching, eviction is cluster-wide only when a distributed L2 (Redis) is registered;
with L1 only, `RemoveByTagAsync` clears the local replica.

### GraphQL query legs: `WithGraphQLCache(...)`

`WithCache(...)` is GET/HEAD-only, so a GraphQL-over-`POST` leg can't use it. Cache a GraphQL **query**
leg with `WithGraphQLCache(...)` instead — same rules and same key (the request body, i.e. the query +
variables, is part of the key, so different queries are different entries), but it opts the `POST` leg
into caching:

```csharp
builder.Backend<Product>("Catalog")
    .WithBody(ctx => GraphQLExtensions.CreateRequest(ProductsQuery))
    .WithGraphQLCache(TimeSpan.FromMinutes(5), tags: ["catalog"]);
```

> **Only cache query operations.** A GraphQL `mutation` also rides `POST`, and Porta can't tell a query
> from a mutation by verb — caching a mutation leg would cache a write. The same fail-closed per-user
> safety applies: a leg that forwards the user's identity must set `varyByUser: true`.

### Full control: cache inside a transformer by hand

When you need behaviour `WithCache(...)` doesn't express — a composite key spanning several legs, a
conditional TTL, tag-based eviction — inject `HybridCache` into a transformer and wrap the call
yourself. The same two rules apply: only cache a leg with a **user-independent** key, and partition the
key by `context.UserId` (or claims) if the leg's data is user-specific.

```csharp
public sealed class DashboardTransformer(HybridCache cache) : TransformerBase<DashboardResponse>
{
    public override async Task<DashboardResponse> TransformAsync(TransformerContext context)
    {
        // Shared, anonymous leg — cache it across all users by a stable key.
        // CallLeg here is your own helper around context.BackendCaller.CallAsync(...).
        var weather = await cache.GetOrCreateAsync(
            $"weather:{context.RouteValues["region"]}",
            async ct => await CallLeg<Weather>(context, "https://weather.internal/now", ct),
            options: new() { Expiration = TimeSpan.FromMinutes(5) },
            cancellationToken: context.CancellationToken);

        // Per-user leg — never cached; calls the backend with the user's forwarded token every time.
        var profile = await CallLeg<Profile>(context, "https://users.internal/me",
            context.CancellationToken, forwardUserToken: true);

        return new DashboardResponse(profile, weather);
    }
}
```

## Related

- [Advanced Topics](advanced.md) — composing other framework conventions onto `.Build()`.
- [Endpoints](endpoints.md) — the endpoint builder and authorization model.
- [HA Deployment](ha-deployment.md) — running multiple replicas and the shared Redis story.
- [Authentication](authentication.md) — backend auth policies and token forwarding.
