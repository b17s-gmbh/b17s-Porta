# Advanced Topics

Porta hooks into ASP.NET Core's minimal API design rather than replacing it. Two facts make
everything in this guide possible:

1. `MapTransformer<...>()`, `MapPassThrough<T>()`, and `MapRawForward()` are extension methods on
   **`IEndpointRouteBuilder`** — the same receiver `MapGet`/`MapPost` use. So anything that produces
   an `IEndpointRouteBuilder` (the app, or a `MapGroup(...)` group) can host Porta endpoints.
2. `.Build()` returns a stock **`RouteHandlerBuilder`** (an `IEndpointConventionBuilder`). So after
   you build a Porta endpoint, you can keep chaining the standard minimal-API conventions onto it —
   `.WithName(...)`, `.WithTags(...)`, `.Produces<T>(...)`, `.RequireRateLimiting(...)`,
   `.CacheOutput(...)`, `.RequireCors(...)`, and `.WithApiVersionSet(...)`.

That second point is the escape hatch: Porta gives you the BFF behaviour (auth context, backend
calls, token exchange, telemetry), and the returned builder lets you bolt on any framework feature
Porta doesn't model itself.

```csharp
app.MapPassThrough<ProductsResponse>()
    .FromGet("/api/products")
    .ToGet("https://products.internal/products")
    .AllowAnonymous()
    .Build()                     // <-- RouteHandlerBuilder from here on
    .WithName("ListProducts")
    .WithTags("Catalog")
    .Produces<ProductsResponse>(StatusCodes.Status200OK);
```

---

## API Versioning

Because Porta builders host on any `IEndpointRouteBuilder` (and `.Build()` returns a
`RouteHandlerBuilder`), the standard
[Asp.Versioning](https://github.com/dotnet/aspnet-api-versioning) library composes directly onto Porta
endpoints. Use **`Asp.Versioning` 10.0.0** — the first release to officially support ASP.NET Core 10
and the built-in OpenAPI library — whose idiomatic minimal-API shape is a *versioned group* created
with `NewVersionedApi()`.

**1. Add the package.** With central package management, add the version to
`Directory.Packages.props`:

```xml
<PackageVersion Include="Asp.Versioning.Http" Version="10.0.0" />
<!-- For per-version OpenAPI documents, also add: -->
<!-- <PackageVersion Include="Asp.Versioning.Mvc.ApiExplorer" Version="10.0.0" /> -->
```

…and reference it (no `Version` attribute) in your BFF's `.csproj`:

```xml
<PackageReference Include="Asp.Versioning.Http" />
```

**2. Register the service.**

```csharp
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1.0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;                       // emits api-supported-versions / api-deprecated-versions
    options.ApiVersionReader = new UrlSegmentApiVersionReader();
    // Or read it elsewhere:
    //   new HeaderApiVersionReader("X-Api-Version")
    //   new QueryStringApiVersionReader("api-version")
    //   ApiVersionReader.Combine(new UrlSegmentApiVersionReader(), new HeaderApiVersionReader("X-Api-Version"))
});
// Per-version OpenAPI (needs Asp.Versioning.Mvc.ApiExplorer) — one call, not one per version:
//   .AddApiExplorer(o => o.GroupNameFormat = "'v'VVV").AddOpenApi();
// then: app.MapOpenApi().WithDocumentPerVersion();  // -> /openapi/v1.json, /openapi/v2.json
```

**3. Map Porta endpoints onto a versioned group.** `NewVersionedApi(...)` returns an
`IEndpointRouteBuilder`, and so does the `MapGroup(...).HasApiVersion(...)` chain — both are valid
Porta hosts, so the Porta builders chain straight off the group.

```csharp
var catalog = app.NewVersionedApi("Catalog");

// v1 — note the {version:apiVersion} segment in the group route for URL-segment versioning
var v1 = catalog.MapGroup("/api/v{version:apiVersion}").HasApiVersion(1.0);
v1.MapPassThrough<ProductsResponse>()
    .FromGet("/products")
    .ToGet("https://products.internal/products")
    .AllowAnonymous()
    .Build();

// v2 — different transformer, different backend, same public route shape
var v2 = catalog.MapGroup("/api/v{version:apiVersion}").HasApiVersion(2.0);
v2.MapTransformer<ProductsV2Transformer, ProductsResponse>()
    .FromGet("/products")
    .ToGet("https://products-v2.internal/products")
    .AllowAnonymous()
    .Build();
```

A request to `/api/v1/products` hits the first endpoint; `/api/v2/products` hits the second; an
unknown version yields a `400` from Asp.Versioning before Porta runs.

**Header / query-string versioning** works the same way — drop the `{version:apiVersion}` route
segment (group on `/api/products` directly), set the matching `ApiVersionReader`, and the client
selects the version via the header or query parameter instead of the path.

**Deprecation** is declarative; combined with `ReportApiVersions = true` it advertises sunset info:

```csharp
var catalog = app.NewVersionedApi("Catalog");
catalog.MapGroup("/api/v{version:apiVersion}").HasDeprecatedApiVersion(1.0);   // -> api-deprecated-versions: 1.0
catalog.MapGroup("/api/v{version:apiVersion}").HasApiVersion(2.0);
```

> **Coexistence:** Asp.Versioning selects endpoints through its own `ApiVersionMatcherPolicy`, and
> Porta's `.When()` uses `WhenPredicateMatcherPolicy`. Both are registered `MatcherPolicy` services,
> so ASP.NET Core runs both and they compose. Just don't gate the *same* dimension twice (e.g. don't
> `.When(header == "2")` **and** `HasApiVersion(2.0)` off the same header) — pick one mechanism per
> version axis.

---

## Grouping endpoints with `MapGroup`

Because the builders extend `IEndpointRouteBuilder`, a `RouteGroupBuilder` from `MapGroup(...)` is a
valid host. Use it to share a route prefix and non-auth conventions across a batch of BFF endpoints:

```csharp
var catalog = app.MapGroup("/api/catalog")
    .WithTags("Catalog");             // tags, CORS, rate limiting, etc. flow down to each endpoint

catalog.MapPassThrough<ProductsResponse>()
    .FromGet("/products")             // -> /api/catalog/products
    .ToGet("https://products.internal/products")
    .Build();

catalog.MapTransformer<ProductDetailTransformer, ProductDetail>()
    .FromGet("/products/{id}")        // -> /api/catalog/products/{id} ({id} is interpolated into the backend URL)
    .ToGet("https://products.internal/products/{id}")
    .Build();
```

The route prefix and group-level conventions like tags, CORS, and rate limiting flow down to each
endpoint.

> **Don't authorize on the group.** Porta owns auth per endpoint: `.Build()` always stamps explicit
> `RequireAuthorization()` or `AllowAnonymous()` metadata based on the endpoint's effective requirement
> (which defaults to *required* via `RequireAuthorizationByDefault`). Because an endpoint-level
> `AllowAnonymous()` overrides a group requirement, a Porta endpoint that resolves to anonymous
> **silently defeats** a group-level `.RequireAuthorization()` — making it redundant at best and a
> security gap at worst. Set auth on the endpoint instead: lean on the `RequireAuthorizationByDefault`
> default, or call `.RequireAuth("policy")` / `.AllowAnonymous()` per endpoint.

---

## OpenAPI / documentation metadata

Porta's handler serializes the transformer result to JSON at runtime, but it does not infer an OpenAPI
response schema for you. If you expose a Swagger/OpenAPI document, describe the contract explicitly on
the returned builder:

```csharp
app.MapTransformer<UserDashboardTransformer, DashboardResponse>()
    .FromGet("/api/dashboard")
    .ToBackends(/* ... */)
    .Build()
    .WithName("GetDashboard")
    .WithSummary("Aggregated user dashboard")
    .WithDescription("Fans out to the profile, orders, and notifications backends.")
    .Produces<DashboardResponse>(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status401Unauthorized)
    .ProducesProblem(StatusCodes.Status502BadGateway);   // Porta returns 502 on backend failure
```

The status codes Porta can emit from the transformer pipeline are worth documenting: `400` (invalid
request body / route value), `401`/`403` (auth), `500` (transformer error), and `502` (backend
unavailable). See [`TransformerEndpointBuilder`](../src/Transformers/TransformerEndpointBuilder.cs) for
the exact mapping.

---

## Composing other framework features

Anything that attaches to a `RouteHandlerBuilder` or `RouteGroupBuilder` works. A few that pair well
with a BFF:

```csharp
// Rate limiting (per-endpoint policy registered via AddRateLimiter)
app.MapPassThrough<SearchResponse>()
    .FromGet("/api/search")
    .ToGet("https://search.internal/search")
    .AllowAnonymous()
    .Build()
    .RequireRateLimiting("search");

// Output caching for cacheable, anonymous reads (AddOutputCache + app.UseOutputCache())
app.MapPassThrough<ProductsResponse>()
    .FromGet("/api/products")
    .ToGet("https://products.internal/products")
    .AllowAnonymous()
    .Build()
    .CacheOutput(p => p.Expire(TimeSpan.FromSeconds(30)));

// CORS for a specific endpoint (AddCors + named policy)
app.MapPassThrough<PublicConfig>()
    .FromGet("/api/config")
    .ToGet("https://config.internal/public")
    .AllowAnonymous()
    .Build()
    .RequireCors("spa");
```

> **Caching caveat:** only cache endpoints whose response does not depend on the user. Anything that
> forwards the user's token (`BackendAuthPolicies.BearerToken`, token exchange) or returns
> per-identity data must not be output-cached at the BFF, or one user can be served another's
> response. Key the cache by the varying dimension, or don't cache it.

---

## Readiness and health

When running multiple replicas behind a load balancer, expose health endpoints so the balancer routes
only to ready instances. These are stock ASP.NET Core health checks — Porta doesn't wrap them:

```csharp
builder.Services.AddHealthChecks();
// ...
app.MapHealthChecks("/healthz");
```

For the full multi-replica story (no sticky sessions, shared data-protection keys, distributed session
store), see [HA Deployment](ha-deployment.md).
