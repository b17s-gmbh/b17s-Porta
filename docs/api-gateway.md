# Using b17s.Porta as an API Gateway

b17s.Porta is, as the name says, primarily a Backend-For-Frontend library. But the same building blocks - typed pass-through, raw forwarding, per-backend auth, header manipulation - also cover a meaningful slice of the "API gateway" problem. This page is an opinionated take on when reaching for this library as a gateway is a good fit, and when you should pick something else.

## TL;DR

Use b17s.Porta as a gateway when you want a **small, code-first, opinionated edge** in front of a known set of internal services - especially if you're already running it as a BFF for a frontend and want to consolidate. Most "missing" gateway features (rate limiting, circuit breaking, etc.) can be added as ASP.NET Core middleware, and you can also place b17s.Porta **behind** another gateway like YARP if you want each tool doing what it's best at. Only switch tools entirely when something fundamental is missing - see [When another tool is the better choice](#when-another-tool-is-the-better-choice).

## Where it fits well

### 1. Auth translation at the edge

This is the strongest gateway use case. Each route can declare its own backend auth policy:

```csharp
app.MapPassThrough<OrderResponse>("GET", "/api/orders/{id}")
    .ToGet($"{ordersUrl}/orders/{{id}}")
    .WithTokenExchange("orders-api")
    .Build();

app.MapRawForward()
    .FromGet("/api/legacy/{**path}")
    .ToGet($"{legacyUrl}/{{**path}}")
    .WithBackendAuth(BackendAuthPolicies.BasicAuth)
    .Build();
```

The caller authenticates once (session cookie or reference token); the gateway swaps in whatever each backend expects (bearer, exchanged token, basic auth, none). See [Authentication](authentication.md) and [Endpoints](endpoints.md) for the full set of policies.

### 2. Zero-code proxying for files and binary content

[`MapRawForward()`](raw-forwarding.md) gives you a streaming proxy without a transformer class - useful for file downloads, uploads, XML APIs, and any non-JSON traffic that would otherwise pay a serialization tax in a typed BFF.

### 3. Header rewriting and request enrichment

Extending `RawForwardTransformer` lets you strip internal headers (`X-Backend-Server`, debug headers) and inject things like tenant IDs or correlation IDs - a classic gateway responsibility. See [Custom Raw Forwarding with Header Manipulation](raw-forwarding.md#custom-raw-forwarding-with-header-manipulation).

### 4. Aggregation that a normal gateway can't do

Most gateways forward 1:1. b17s.Porta can fan out to several backends and return a single composed response via `AggregatingTransformer<T>`. If your "gateway" needs are really "I want a typed facade that hides three services behind one endpoint," this is the sweet spot.

### 5. OpenTelemetry out of the box

All transformers and backend calls are auto-instrumented ([Telemetry](telemetry.md)). You get distributed traces across the edge without wiring anything up - comparable to what a real gateway gives you.

### 6. Consolidating with an existing BFF

If you're already running b17s.Porta for a frontend and have a small handful of additional service-to-service routes that need auth translation or aggregation, adding them as gateway-style endpoints is cheaper than introducing a second piece of infrastructure.

## Extending b17s.Porta to cover more gateway concerns

If b17s.Porta fits 90% of what you need, don't switch tools for the last 10%. The library is a normal ASP.NET Core app, so most classic gateway features can be layered on without giving up what you already have.

### Add rate limiting with ASP.NET Core middleware

`Microsoft.AspNetCore.RateLimiting` (built into .NET 7+) plugs in cleanly:

```csharp
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("per-user", opts =>
    {
        opts.PermitLimit = 100;
        opts.Window = TimeSpan.FromMinutes(1);
    });
});

var app = builder.Build();

app.UseRateLimiter();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapPassThrough<ProductsResponse>("GET", "/api/products")
    .ToGet($"{productsUrl}/products")
    .Build()
    .RequireRateLimiting("per-user");
```

Apply globally, per route group, or per endpoint - same as any ASP.NET Core app.

### Add circuit breaking and retries with Polly

The backend caller already has timeouts and basic retries (see [Configuration](configuration.md)). For richer policies - circuit breakers, bulkheads, jittered retries - register `Microsoft.Extensions.Http.Resilience` handlers on the named HttpClients the library uses, or wrap your own `IBackendCaller` decorator.

### Add request validation, IP allowlisting, or custom auth

Standard ASP.NET Core middleware applies. Drop it into the pipeline before the BFF endpoints; nothing in the library prevents it.

### Put b17s.Porta behind YARP (or any reverse proxy)

When you want **dynamic routing for many services** *and* the typed composition b17s.Porta gives you for a few key endpoints, run them as a pair. YARP at the edge handles wildcard routing, load balancing across replicas, and traffic shaping. b17s.Porta runs behind it as one of the upstreams, owning the routes that need auth translation, aggregation, or a typed facade.

```
┌──────────┐      ┌──────────────┐      ┌────────────────┐
│ Clients  │ ───▶ │   YARP / APIM │ ───▶ │ b17s.Porta       │ ──▶ backends
└──────────┘      │ (wildcards,  │      │ (typed/aggreg.)│
                  │  rate limit, │      └────────────────┘
                  │  LB, quotas) │ ───▶ ┌────────────────┐
                  └──────────────┘      │ other services │
                                        └────────────────┘
```

This is also the right shape if a platform team owns the edge and wants config-driven routing, while application teams own the BFF.

### Use a service mesh for cross-cutting infra concerns

mTLS, retries, circuit breaking, and observability between services are well-handled by **Linkerd** or **Istio** - and they don't conflict with running b17s.Porta as the API surface.

## When another tool is the better choice

These are the cases where extending or fronting b17s.Porta doesn't really help - the mismatch is fundamental.

### You need a public, multi-tenant edge with API products, quotas, and a developer portal

That's API-Management territory: API products, plans, self-service onboarding, key management, billing. **Kong**, **Azure API Management**, **Apigee**, **AWS API Gateway**, **Tyk** are built for this. You could put one in front of b17s.Porta, but if API management *is* the primary requirement, the BFF role is secondary and you should start from the APIM side.

### You need protocol bridging beyond HTTP

gRPC, WebSockets-as-first-class, MQTT, AMQP - none of these are in scope. b17s.Porta is HTTP/JSON-first, with raw HTTP pass-through for non-JSON payloads. Use a protocol-aware gateway (**Envoy**, **Kong**) or terminate those protocols elsewhere.

### Your edge config must be owned and changed by an ops team without redeploys

Routes, auth policies, and transformers live in C#. If the operating model requires YAML, a UI, or hot reload, you'll fight the library. Either run a real gateway at the edge (with b17s.Porta behind it for the parts where typed composition still pays off), or pick a config-driven gateway outright.

## Decision checklist

Pick b17s.Porta as a gateway if **most** of these are true:

- [ ] Your routes are known at build time and change with code, not config.
- [ ] You have a small-to-medium number of backends (roughly: tens, not hundreds).
- [ ] Your edge concerns are auth translation, header rewriting, and optional aggregation.
- [ ] Reference tokens (or anonymous) are acceptable for caller auth.
- [ ] You're comfortable adding rate limiting / circuit breaking via ASP.NET Core middleware, or fronting with YARP / APIM.
- [ ] You're already running it as a BFF and want to avoid a second piece of infrastructure.

Missing one or two of these usually means **add middleware or a proxy in front**, not switch tools. Switch only when one of the [fundamental mismatches](#when-another-tool-is-the-better-choice) above applies.

## Related

- [Endpoints](endpoints.md) - routing, builders, authorization
- [Raw Forwarding](raw-forwarding.md) - zero-code proxying and header manipulation
- [Authentication](authentication.md) - backend auth policies
- [Telemetry](telemetry.md) - tracing across the edge
