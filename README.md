# b17s.Porta

Porta is your way to create completely customizable, easy-to-implement, boiler-plate code free Backend-For-Frontend (BFF) services with opinionated, sensible defaults.
Its architecture hooks into ASP.Net Core's minimal API design, and extends it via transformer-based API aggregation with multi-frontend/backend authentication support.

> **Pre-1.0 — review before production use.** Porta is safe behind a hardened reverse proxy with standard OIDC, session, or reference-token flows. Edge deployments (direct internet exposure, untrusted tenants, shared-host environments) need extra middleware hardening. Treat Porta's log stream as Secret-classified. See [SECURITY.md](SECURITY.md#deployment-posture) for the deployment posture and [log sensitivity](SECURITY.md#sensitive-data-in-logs) details.

## Features

- **Transformer Pattern**: Clean separation between API contracts and backend calls
- **Multi-Backend Aggregation**: Combine data from multiple backends in a single endpoint
- **Per-Backend Authentication**: Configure different auth policies for each backend
- **Startup Validation**: Catch configuration errors at application startup, not runtime
- **OIDC Endpoints**: Opt-in login, logout, and back-channel logout middleware
- **Session Administration**: Opt-in REST endpoints for session management
- **Raw Forwarding**: Zero-code proxy endpoints for binary content, files, and non-JSON APIs
- **GraphQL Support**: REST facade over GraphQL backends
- **OpenTelemetry**: Automatic distributed tracing for all transformers and backend calls

## Installation

```bash
dotnet add package b17s.Porta
```

## Quick Start

### Minimal Setup (No Auth)

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPortaCore(options => {
    options.DefaultTimeout = TimeSpan.FromSeconds(30);
});

var app = builder.Build();

app.MapPassThrough<ProductsResponse>("GET", "/api/products")
    .ToGet("https://products-api.internal/products")
    .AllowAnonymous()
    .Build();

app.Run();
```

> **Note**: endpoints require authorization by default (`PortaCoreOptions.RequireAuthorizationByDefault = true`). Drop `.AllowAnonymous()` only when you've configured an authentication scheme. Flip the option to `false` to invert the default if you'd rather opt *into* auth per endpoint.

### With OIDC Authentication

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPortaCore(options => {
    options.TrustedHosts = ["https://api.internal.example.com"];
});

builder.Services.AddPortaAuthentication(builder.Configuration);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapTransformer<UserProfileTransformer, UserProfile>()
    .FromGet("/api/profile")
    .ToPost("https://api.internal.example.com/userinfo")
    .WithBackendAuth(BackendAuthPolicies.BearerToken)
    .Build();

app.Run();
```

## Documentation

| Topic | Description |
|-------|-------------|
| [Configuration](docs/configuration.md) | Service registration, options, and production settings |
| [Transformers](docs/transformers.md) | Writing transformers, base classes, and error handling |
| [Endpoints](docs/endpoints.md) | Endpoint builder, routing, and authorization |
| [Authentication](docs/authentication.md) | User auth providers and backend auth handlers |
| [OIDC Endpoints](docs/oidc.md) | Login, logout, back-channel logout, and session admin |
| [Raw Forwarding](docs/raw-forwarding.md) | Binary content, file proxying, and streaming |
| [GraphQL](docs/graphql.md) | Calling GraphQL backends from REST endpoints |
| [Telemetry](docs/telemetry.md) | OpenTelemetry traces and metrics |
| [HA Deployment](docs/ha-deployment.md) | Running multiple replicas behind a load balancer without sticky sessions |
| [API Gateway Use](docs/api-gateway.md) | When to use this library as a gateway, and when to pick something else |

## Transformer Hierarchy

Choose the right base class for your use case:

| Base Class | Use Case | Code Required |
|------------|----------|---------------|
| `MapPassThrough<T>()` | Zero-code pass-through | Config only |
| `PassThroughTransformer<T>` | Simple pass-through | 1 line |
| `AuthenticatedTransformer<T>` | Auth required, no request body | 1 line |
| `AuthenticatedTransformer<TReq, TRes>` | Auth + backend request body | 2-3 lines |
| `AggregatingTransformer<T>` | Multi-backend aggregation | ~15 lines |
| `TransformerBase<T>` | Full custom control | Varies |

## Backend Authentication

Built-in policies:

| Policy | Description | Requires User |
|--------|-------------|---------------|
| `None` | No authentication | No |
| `BasicAuth` | HTTP Basic auth from config | No |
| `BearerToken` | Forward user's token | Yes |
| `TokenExchange` | Exchange for backend token (needs an audience - see [Authentication](docs/authentication.md#backend-authentication)) | Yes |

Per-backend configuration:

```csharp
app.MapTransformer<MyTransformer, Response>()
    .FromGet("/api/data")
    .ToBackends(b => b
        .ToGet("Users", $"{usersUrl}/api").WithAuth(BackendAuthPolicies.BearerToken)
        .ToGet("Products", $"{productsUrl}/api").WithAuth(BackendAuthPolicies.BasicAuth))
    .Build();
```
