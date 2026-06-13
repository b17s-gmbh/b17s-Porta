# b17s.Porta

[![CI](https://github.com/b17s-gmbh/b17s-Porta/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/b17s-gmbh/b17s-Porta/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/b17s.Porta.svg)](https://www.nuget.org/packages/b17s.Porta/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Porta is your way to create completely customizable, easy-to-implement, boiler-plate code free Backend-For-Frontend (BFF) services with opinionated, sensible defaults.
Its architecture hooks into ASP.Net Core's minimal API design, and extends it via transformer-based API aggregation with multi-frontend/backend authentication support.

> **IMPORTANT** Porta is not yet battle-hardened. For this reason it is adviced to not use it on edge yet, but have a reverse proxy in front of it.

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

### Minimal Setup (Mapped Passthrough; No Auth)

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPortaCore();

var app = builder.Build();

app.FromGet<ProductsResponse>("/api/products")
    .ToGet("https://products-api.internal/products")
    .AllowAnonymous()
    .Build();

app.Run();
```

> **Note**: endpoints require authorization by default (`PortaCoreOptions.RequireAuthorizationByDefault = true`). Drop `.AllowAnonymous()` only when you've configured an authentication scheme. Flip the option to `false` to invert the default if you'd rather opt *into* auth per endpoint.

### With OIDC Authentication

```csharp // TODO: FIX Example. Not good to mix introducing auth and transformer in one go.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPortaCore(options => {
    options.TrustedHosts = ["https://api.internal.example.com"];
});

builder.Services.AddPortaAuthentication(builder.Configuration);
builder.Services.AddTransformer<UserProfileTransformer>();

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

// TODO: Add RAW passthrough example

// TODO: Add example introducing transformer inkcluding a small transformer

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

## Try it (runnable demo)

A self-contained, run-out-of-the-box demo lives in [demo/](demo/README.md). One command brings up a
complete BFF topology against **two** identity providers — Keycloak and Zitadel — orchestrated by
.NET Aspire, plus end-to-end login tests against both:

```bash
cd demo
aspire run          # or: dotnet run --project Demo.AppHost
```

A container runtime (Docker Desktop or Podman) is the only prerequisite — the IdPs, database, and
seeded test users are provisioned automatically. See [demo/README.md](demo/README.md) for the topology,
seeded credentials, exposed endpoints, and how to run the functional/E2E suite.

## Transformer Hierarchy

Choose the right base class for your use case:

// TODO: Add link for each transformer to the matching doc and and example

| Base Class | Use Case | Code Required |
|------------|----------|---------------|
| `MapPassThrough<T>()` | Zero-code pass-through | Config only |
| `PassThroughTransformer<T>` | Simple pass-through | 1 line |
| `AuthenticatedTransformer<T>` | Auth required, no request body | 1 line |
| `AuthenticatedTransformer<TReq, TRes>` | Auth + backend request body | 2-3 lines |
| `AggregatingTransformer<T>` | Multi-backend aggregation | ~15 lines |
| `TransformerBase<T>` | Full custom control | Varies |

## Backend Authentication // TODO: Add Custom and explain that you can implement interface to support custom auth

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
