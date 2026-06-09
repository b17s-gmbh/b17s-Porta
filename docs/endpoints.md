# Endpoint Configuration

The BFF framework uses a fluent builder pattern for configuring endpoints. The vocabulary documented here (`FromGet/Post/...`, `FromAny`, `ToGet/Post/...`, `ToAny`, `.When(...)`, `RequireAuth/AllowAnonymous`, `WithBackendAuth/WithTokenExchange/WithRetries`, `Build()`) is shared between `MapTransformer<...>()` and `MapPassThrough<T>()` - the examples below use `MapTransformer` but apply to both. The one exception is `ToBackends(...)`, which is only available on `MapTransformer` (multi-backend aggregation is by definition not a pass-through concern). `MapRawForward()` is a separate streaming builder with its own - smaller - surface (it shares the `FromGet/...` and `ToGet/...` verb sugar); see [Raw Forwarding](raw-forwarding.md).

## Basic Endpoint Registration

```csharp
app.MapTransformer<MyTransformer, MyResponse>()
    .FromGet("/api/products")
    .ToGet($"{backendUrl}/products")
    .Build();
```

## HTTP Method Helpers

Instead of passing the verb as a string to `.FromRoute("METHOD", pattern)` / `.ToBackend("METHOD", url)`, use the method-specific shorthands:

```csharp
// These are equivalent:
.FromRoute("GET", "/api/products")
.FromGet("/api/products")

// ...as are these:
.ToBackend("GET", $"{backendUrl}/products")
.ToGet($"{backendUrl}/products")

// All supported incoming-route helpers:
.FromGet("/api/products")
.FromPost("/api/products")
.FromPut("/api/products/{id}")
.FromDelete("/api/products/{id}")
.FromPatch("/api/products/{id}")
.FromHead("/api/products")
.FromOptions("/api/products")

// All supported backend helpers (GET/POST/PUT/DELETE/PATCH):
.ToGet($"{backendUrl}/products")
.ToPost($"{backendUrl}/products")
.ToPut($"{backendUrl}/products/{{id}}")
.ToDelete($"{backendUrl}/products/{{id}}")
.ToPatch($"{backendUrl}/products/{{id}}")
```

Reach for the string form (`.ToBackend("HEAD", url)`) only for verbs without a shorthand. The backend helpers keep the optional `ContentType` argument: `.ToPost(url, ContentType.Xml)`. `.ToAny(url)` (method-preserving proxy) and `.ToGraphQL(url)` round out the backend vocabulary.

## Wildcard HTTP Method Matching

For endpoints that should handle any HTTP method:

```csharp
// Match any HTTP method on the route
app.MapTransformer<ResourceTransformer, ResourceResponse>()
    .FromAny("/api/resource/{id}")
    .ToGet($"{backend}/resource/{{id}}")  // Fixed backend method
    .Build();

// Method-preserving proxy: incoming method = backend method
app.MapTransformer<ProxyTransformer, object>()
    .FromAny("/api/proxy/{**path}")
    .ToAny($"{backend}/{{**path}}")  // POST in = POST out, GET in = GET out
    .Build();
```

The transformer can access the actual HTTP method via `context.HttpContext.Request.Method`.

## Route Parameter Interpolation

Route parameters captured by `FromRoute`/`FromGet`/... are substituted into the backend URL
template (`ToBackend`/`ToGet`/.../`ToAny`, plus `ToGraphQL` on `MapTransformer`/`MapPassThrough`;
`MapRawForward` exposes `ToBackend`/`ToGet`/.../`ToAny`) by matching `{name}` placeholders against the
captured route values. This interpolation is shared by `MapTransformer`, `MapPassThrough`, and
`MapRawForward`, and is a **security boundary**: a value an attacker controls must not be able
to change the backend scheme/host/port or escape the template's static path prefix.

Two placeholder forms, with different encoding:

```csharp
// Single segment: {id} encodes the value as ONE path segment. A '/' in the value becomes
// %2F, so it can never inject an extra segment or pivot the authority.
app.MapPassThrough<ProductResponse>("GET", "/api/products/{id}")
    .ToGet($"{backend}/products/{{id}}")
    .Build();
// /api/products/42        -> {backend}/products/42
// /api/products/a%2Fb     -> {backend}/products/a%2Fb   (slash stays encoded)

// Catch-all: {*path} or {**path} is the subtree-proxy opt-in. The matched value's '/'
// separators are PRESERVED so a nested request path maps to a nested backend path. Each
// individual segment is still encoded (so '@'/':' inside a segment can't pivot the authority).
app.MapRawForward("GET", "/api/proxy/{**path}")
    .ToGet($"{backend}/{{**path}}")
    .Build();
// /api/proxy/a/b/c        -> {backend}/a/b/c
```

Use a catch-all placeholder in **both** the route and the backend template when proxying a
subtree. Note the backend template must use the catch-all syntax too (`{{**path}}`), not a bare
`{{path}}` — a bare placeholder is single-segment and would percent-encode the separators
(`a%2Fb%2Fc`).

Regardless of form, the following are **rejected** with an `InvalidRouteValueException` (surfaced
as a `400`-class failure) so they can never reach the backend:

- `.` / `..` path-traversal segments (e.g. `../admin`)
- literal `?`, `#`, or `\` (query/fragment/path smuggling)
- pre-encoded separators or dots (`%2F`, `%5C`, `%2E`) that `Uri` canonicalization would collapse

As defense-in-depth, the fully interpolated URL is re-parsed and its scheme/host/port and path
prefix are compared against the static portion of the template; anything that moved outside the
configured backend is rejected even if it slipped past per-segment encoding.

## Conditional Route Matching

Use `.When()` to add a runtime predicate for conditional endpoint selection:

```csharp
// API versioning via header
app.MapTransformer<ProductsV2Transformer, ProductsResponse>()
    .FromGet("/api/products")
    .When(ctx => ctx.Request.Headers["X-Api-Version"] == "2")
    .ToGet($"{v2Backend}/products")
    .Build();

// A/B testing - route based on cookie
app.MapTransformer<NewCheckoutTransformer, CheckoutResponse>()
    .FromPost("/api/checkout")
    .When(ctx => ctx.Request.Cookies["feature_new_checkout"] == "true")
    .ToPost($"{newCheckoutBackend}/checkout")
    .Build();

// Feature flag - route based on query parameter
app.MapTransformer<ExperimentalTransformer, Response>()
    .FromGet("/api/search")
    .When(ctx => ctx.Request.Query["experimental"] == "true")
    .ToGet($"{experimentalBackend}/search")
    .Build();

// Fallback endpoint (no constraint - catches all remaining requests)
app.MapTransformer<ProductsTransformer, ProductsResponse>()
    .FromGet("/api/products")
    .ToGet($"{defaultBackend}/products")
    .Build();
```

**How it works:**
- The predicate runs during ASP.NET Core's endpoint selection phase (before authorization)
- If the predicate returns `false`, the endpoint is skipped and other matching routes are tried
- Endpoints without `.When()` always match (useful as fallbacks)
- Keep predicates simple for performance - they run on every matching request

## Multi-Backend Endpoints

Configure multiple backends for aggregation:

```csharp
app.MapTransformer<MyTransformer, MyResponse>()
    .FromGet("/api/aggregated")
    .ToBackends(b => b
        .ToPost("UserInfo", $"{userServiceUrl}/userinfo").WithAuth(BackendAuthPolicies.BasicAuth)
        .ToGet("Products", $"{productServiceUrl}/products").WithAuth(BackendAuthPolicies.BearerToken))
    .Build();
```

The `ToBackends(configure => ...)` builder adds a backend per `ToGet/ToPost/...` call; the per-backend modifiers (`WithAuth`, `WithUserToken`, `WithTokenExchange`, `WithTimeout`, `WithRetries`) apply to the backend they follow. See [Transformers](transformers.md#declaring-named-backends-fluently) for the full surface.

### Backend Tuple Syntax

`ToBackends(...)` also accepts an array of `NamedBackendEndpoint` values if you'd rather build them yourself. The terse way is the `(name, method, url)` tuple plus a fluent modifier:

```csharp
// Basic 3-tuple (no auth)
("BackendName", "GET", "http://backend/api/endpoint")

// With specific auth policy
("BackendName", "GET", "http://backend/api/endpoint").WithAuth(BackendAuthPolicies.BasicAuth)

// Forward user's OAuth token
("BackendName", "GET", "http://internal-service/api/endpoint").WithUserToken()

// Token exchange for backend-specific token
("BackendName", "GET", "http://other-service/api/endpoint").WithTokenExchange("other-api-audience")

// With custom timeout
("BackendName", "GET", "http://backend/api/endpoint").WithAuth(...).WithTimeout(TimeSpan.FromSeconds(10))

// With automatic retries
("BackendName", "GET", "http://backend/api/endpoint").WithAuth(...).WithRetries(3)
```

`WithRetries(n)` retries transient backend failures (5xx, connection errors, timeouts) with exponential backoff. The count is **per endpoint** - each backend retries the number of attempts it declares. `PortaCore:MaxRetryAttempts` (default `3`) is the app-wide **ceiling**, so the effective count is `min(n, MaxRetryAttempts)`; raise the ceiling to let endpoints request more, or set it to `0` to disable retries app-wide. Endpoints that never call `WithRetries(...)` are not retried.

## Refresh-on-401 Retry

A backend `401` on a `BearerToken`/`TokenExchange` endpoint triggers a one-shot user-token refresh and a single retry with the rotated token. This is **on by default** - no builder call needed - and disabled globally via `PortaCore:RefreshBackendTokenOn401 = false`. It is bounded (one refresh + one retry, skipped when the token doesn't rotate) and concurrency-safe across aggregation. See [Authentication](authentication.md#refreshing-the-user-token-on-a-backend-401) for the full behavior and caveats.

## Endpoint Authorization

Endpoints require user authorization by default.

### Global Default

```csharp
builder.Services.AddPortaCore(options =>
{
    // Default: true - all endpoints require authorization
    options.RequireAuthorizationByDefault = true;
});
```

### Per-Endpoint Override

```csharp
// Uses default (RequireAuthorizationByDefault)
app.MapTransformer<ProtectedTransformer, Response>()
    .FromGet("/api/protected")
    .ToGet($"{backendUrl}/data")
    .Build();

// Explicitly require auth with a specific policy
app.MapTransformer<AdminTransformer, Response>()
    .FromGet("/api/admin")
    .ToGet($"{backendUrl}/admin")
    .RequireAuth("AdminPolicy")
    .Build();

// Allow anonymous access
app.MapTransformer<PublicTransformer, Response>()
    .FromGet("/api/public")
    .ToGet($"{backendUrl}/public")
    .AllowAnonymous()
    .Build();

// Anonymous with optional auth - populate auth context if available
app.MapTransformer<ProductTransformer, ProductResponse>()
    .FromGet("/api/products/{id}")
    .ToGet($"{backendUrl}/products/{{id}}")
    .AllowAnonymousWithOptionalAuth()
    .Build();
```

### Optional Authentication

Use `.AllowAnonymousWithOptionalAuth()` for endpoints that work for both authenticated and anonymous users:

```csharp
public class ProductTransformer : TransformerBase<ProductResponse>
{
    public override async Task<ProductResponse> TransformAsync(TransformerContext context)
    {
        var product = await CallBackendAsync<Product>(context);

        if (context.AuthContext.IsAuthenticated)
        {
            // Show personalized recommendations
            product.Recommendations = await GetPersonalizedRecommendations(context);
        }
        else
        {
            // Show generic recommendations
            product.Recommendations = await GetPopularProducts(context);
        }

        return product;
    }
}
```

**Use cases:**
- Product pages with personalized recommendations for logged-in users
- APIs that return different data based on authentication status
- Endpoints where auth is optional but enhances functionality

## Authorization Validation

If any backend requires user identity but `AllowAnonymous()` is used, the application fails to start:

```
InvalidOperationException: Endpoint '/api/data' has backends that require user identity but
AllowAnonymous() was called. Remove AllowAnonymous() or change backend auth policies.
Backends requiring identity: ['InternalApi' (policy: BearerToken)]
```
