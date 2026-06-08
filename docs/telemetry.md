# Telemetry

The BFF framework automatically generates OpenTelemetry traces and metrics for all transformer executions and backend calls. This is enabled by default and requires no additional code in transformer implementations.

## Automatic Instrumentation

When `EnableTelemetry` is true (default), the framework automatically instruments transformer and raw-forward endpoint execution, backend HTTP calls, token exchange, the session-admin endpoint, and OIDC back-channel logout. Activities are emitted by `PortaActivitySource` (source name `b17s.Porta`) and metrics by `PortaMetrics` on the same meter name.

The table below lists the spans and metrics the framework **emits today**. Each activity uses a **fixed category name**; the specific transformer/backend is carried on a **tag**, never baked into the activity name (see the note below). A handful of additional instruments are declared on the source/meter but not yet recorded - see [Reserved instruments](#reserved-instruments-declared-but-not-yet-emitted).

| Component | Activity name | Related metrics |
|-----------|---------------|-----------------|
| Transformer execution | `bff.transformation` (with `bff.transformation.strategy` tag set to the transformer class name) | `bff.transformation.duration` |
| Raw-forward execution | `bff.raw_forward` (with `bff.transformation.strategy` tag set to the transformer class name and `bff.component` = `raw_forward`) | `bff.transformation.duration` (`strategy` = `RawForward:{name}`) |
| Backend HTTP calls | `bff.backend` (with `bff.backend.service` tag set to the service hostname) | `bff.backend.duration`, `bff.backend.requests`, `bff.backend.errors` |
| Aggregator child spans | `bff.backend` (one per parallel backend, `bff.component` = `aggregator`, parented to the transformation activity) | `bff.backend.duration`, `bff.backend.requests`, `bff.backend.errors` (from the inner backend call) |
| Token exchange | `bff.token_exchange` | - |
| Session-admin endpoint | `bff.session_admin` | - |
| OIDC back-channel logout | `bff.backchannel_logout` | - |
| Refresh-lock cleanup timer | - | `bff.session.lock_cleanup_runs`, `bff.session.stale_locks_cleaned` |

> Activity names are **fixed category strings** (`bff.transformation`, `bff.raw_forward`, `bff.backend`, …). The literal `bff.transformer.{Name}` / `bff.backend.{ServiceName}` strings you may have seen in older revisions of this doc are *display* shapes only - at runtime each span carries its category as the activity name plus a tag (`bff.transformation.strategy`, `bff.backend.service`) that names the specific transformer or backend. **Search by tag, not by composed activity name.**

### Reserved instruments (declared but not yet emitted)

`PortaActivitySource` and `PortaMetrics` declare a broader set of instruments than the framework currently records. The following are **defined on the source/meter but are not emitted by any production code path yet** - queries against them return no data. They are reserved for upcoming releases; do not build dashboards or alerts on them until they appear in the table above.

- **Spans:** `bff.request`, `bff.authentication`, `bff.token_refresh`, `bff.session`, `bff.health_check`
- **Metrics:** `bff.request.duration`, `bff.request.size`, `bff.response.size`, `bff.requests.active`, `bff.auth.failures`, `bff.auth.successes`, `bff.auth.duration`, `bff.token.refreshes`, `bff.token.refresh_failures`, `bff.csrf.validation_failures`, `bff.session.created`, `bff.session.invalidated`, `bff.sessions.active`

## Metric reference

All counters and histograms below are declared under the `b17s.Porta` meter. Source of truth is [`PortaMetrics.cs`](../src/Telemetry/PortaMetrics.cs) - when in doubt, read the meter declarations there. The **Status** column reflects what the framework records today: `Emitted` instruments produce data; `Reserved` instruments are declared on the meter but not yet recorded by any production code path (see [Reserved instruments](#reserved-instruments-declared-but-not-yet-emitted)).

### Counters

| Metric | Tags | Status | Description |
|--------|------|--------|-------------|
| `bff.backend.requests` | `service`, `protocol`, `status_code` | Emitted | Backend HTTP requests. |
| `bff.backend.errors` | `service`, `protocol`, `status_code` | Emitted | Backend requests with `status_code >= 400`. |
| `bff.session.lock_cleanup_runs` | - | Emitted | Stale-lock cleanup timer executions. |
| `bff.session.stale_locks_cleaned` | - | Emitted | Stale per-user refresh locks reclaimed. |
| `bff.auth.failures` | `reason`, `provider` (optional) | Reserved | Authentication failures. |
| `bff.auth.successes` | `provider` (optional) | Reserved | Successful authentications. |
| `bff.token.refreshes` | `reason` (optional) | Reserved | Successful token refreshes at the IdP. |
| `bff.token.refresh_failures` | `reason` (optional) | Reserved | Failed token refreshes. |
| `bff.csrf.validation_failures` | `reason` | Reserved | Antiforgery/CSRF validation failures. |
| `bff.session.created` | - | Reserved | Sessions created (also increments `bff.sessions.active`). |
| `bff.session.invalidated` | `reason` | Reserved | Sessions invalidated (also decrements `bff.sessions.active`). |

### Histograms

| Metric | Unit | Tags | Status | Description |
|--------|------|------|--------|-------------|
| `bff.backend.duration` | `ms` | `service`, `protocol` | Emitted | Backend call duration. |
| `bff.transformation.duration` | `ms` | `strategy` | Emitted | Time spent inside the transformer's `TransformAsync` (raw-forward records `strategy` = `RawForward:{name}`). |
| `bff.request.duration` | `ms` | `method`, `route`, `status_code` | Reserved | End-to-end request processing time. |
| `bff.auth.duration` | `ms` | `provider` | Reserved | Time spent in `IAuthenticationProvider.GetAuthContextAsync`. |
| `bff.request.size` | `bytes` | `method` | Reserved | Incoming request body size. |
| `bff.response.size` | `bytes` | `status_code` | Reserved | Outgoing response body size. |

Latency histograms use the OpenTelemetry `http.server.request.duration`-style buckets (`0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000` ms). Size histograms cover `256 B → 256 MiB` so the `MaxBackendResponseBytes` (10 MiB) and `MaxRawForwardResponseBytes` (100 MiB) caps land in real buckets.

### UpDownCounters

| Metric | Status | Description |
|--------|--------|-------------|
| `bff.sessions.active` | Reserved | Active sessions. Incremented on `bff.session.created`, decremented on `bff.session.invalidated`. |
| `bff.requests.active` | Reserved | In-flight requests. |

## Span Hierarchy

Activity names are the fixed category strings (`bff.transformation`, `bff.backend`); the specific transformer/backend is carried on a tag, not baked into the name (see the note under [Automatic Instrumentation](#automatic-instrumentation)). Porta's top-level endpoint span (`bff.transformation` here) is parented directly under the host's ambient ASP.NET Core request activity. The tags are shown in brackets below:

```
Incoming HTTP Request
└── ASP.NET Core Activity (auto)
    └── bff.transformation                [bff.transformation.strategy = EnrichedUserProfileTransformer]
        ├── bff.backend                   [bff.backend.service = api.internal.com]
        │   └── HTTP GET api.internal.com (auto)
        └── bff.backend                   [bff.backend.service = products.internal.com]
            └── HTTP GET products.internal.com (auto)
```

## Trace Context Propagation

W3C Trace Context headers (`traceparent`, `tracestate`) are automatically propagated to all backend HTTP calls via `AddHttpClientInstrumentation()`. This enables end-to-end distributed tracing across services.

## Configuration

```csharp
builder.Services.AddPortaCore(options =>
{
    // Disable telemetry if needed (default: true)
    options.EnableTelemetry = false;
});
```

## Tags and Attributes

Activity tags emitted by `PortaActivitySource`. Source of truth is [`PortaActivitySource.cs`](../src/Telemetry/PortaActivitySource.cs).

### General

- `bff.service.name`
- `bff.component` - `"transformer"`, `"aggregator"`, `"backend"`, etc.

### HTTP

- `http.method`, `http.url`, `http.status_code`, `http.route`

### Backend

- `bff.backend.service` - service hostname
- `bff.backend.protocol` - `"http"`
- `bff.backend.endpoint`, `bff.backend.operation`

### Transformation

- `bff.transformation.strategy` - transformer class name
- `bff.transformation.rule`

### Authentication

- `bff.auth.provider` - `"SessionAuthProvider"`, `"JwtBearerAuthProvider"`, `"ReferenceTokenAuthProvider"`, etc.
- `bff.auth.user_id`
- `bff.auth.token_type`

### Session

- `bff.session.id`
- `bff.session.user_id`

### Health check

- `bff.health.status`, `bff.health.backend_count`

### Errors

- `error.type`, `error.message`

Stack traces are intentionally **not** exposed as a tag (high cardinality + inner-exception messages frequently contain PII). Use `Activity.AddException(ex)` instead, which records the stack trace as event-scoped attributes per OpenTelemetry semantic conventions.

## Exporting Traces

Traces are exported when `OTEL_EXPORTER_OTLP_ENDPOINT` is configured. The activity source is registered with OpenTelemetry in ServiceDefaults.

### Example: Jaeger

```bash
# Start Jaeger
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest

# Configure app
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
```

### Example: Aspire Dashboard

When running with .NET Aspire, traces are automatically exported to the Aspire dashboard.

## Backend Call Logging

`BackendCaller` separates structured *metadata* logs from *body* logs so that production log sinks do not capture sensitive payloads (access tokens, refresh tokens, PII) by default.

| Event ID | Level | What it logs |
|----------|-------|--------------|
| 14005 `BackendErrorResponseMeta` | Warning | URL, status, reason, body size, content-type |
| 14006 `BackendDeserializationFailed` | Error | URL, status, body size, exception |
| 14007 `BackendResponseMeta` | Debug | URL, status, body size, content-type |
| 14015 `BackendErrorResponseBody` | **Trace** | Error response body, capped by `PortaCore:MaxBodyLogLength` |
| 14016 `BackendDeserializationFailedBody` | **Trace** | Body that failed to deserialize, capped by `PortaCore:MaxBodyLogLength` |
| 14017 `BackendResponseBody` | **Trace** | Response body, capped by `PortaCore:MaxBodyLogLength` |

Body logs are emitted at `LogLevel.Trace`, which is disabled by default in production. Enable Trace only for the `b17s.Porta.Transformers.BackendCaller` category in development or with operator approval - never enable it globally on a system that brokers tokens or PII.

### Body length cap (`PortaCore:MaxBodyLogLength`)

To bound the blast radius of accidentally enabling Trace logs, body events 14015/14016/14017 are truncated to the first `MaxBodyLogLength` characters (default `512`). Truncated entries get a `… (truncated, N chars total)` suffix so you can still see the full size in the meta log (14005/14006/14007).

| Value | Behavior |
|-------|----------|
| `> 0` | Truncate body to N characters (default `512`) |
| `0` | Do not emit body events at all - only metadata logs are written |
| `-1` | Unlimited; full body is logged |

GraphQL responses and any payload that may include access tokens, refresh tokens, or PII (e.g. `me { ... }` queries, OIDC userinfo) should keep the default cap. Set `-1` only in isolated development environments where you have already accepted the risk.
