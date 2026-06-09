# Configuration

## Service Registration

The BFF library uses a modular registration approach with opt-in authentication.

### AddPortaCore() - Core Services

Registers the minimum required services for transformer-based API aggregation. **This is always required.**

```csharp
builder.Services.AddPortaCore(options => {
    // Trusted hosts for user token forwarding (WithUserToken())
    options.TrustedHosts = ["https://api.example.com", "https://*.internal.example.com"];

    // Default timeout for backend calls (default: 30 seconds)
    options.DefaultTimeout = TimeSpan.FromSeconds(30);

    // App-wide ceiling for per-endpoint .WithRetries(n). Each endpoint retries
    // min(n, MaxRetryAttempts) times; endpoints that never call .WithRetries(...)
    // do not retry. Used for the retry pipeline when retries are enabled (default: 3).
    options.MaxRetryAttempts = 3;

    // Refresh the user token and retry once on a backend 401 (default: true)
    options.RefreshBackendTokenOn401 = true;

    // Require authorization by default (default: true)
    options.RequireAuthorizationByDefault = true;

    // Enable OpenTelemetry instrumentation (default: true)
    options.EnableTelemetry = true;

    // Cap on backend response body characters written to Trace logs (default: 512).
    // -1 = unlimited; 0 = disable body logs entirely. See docs/telemetry.md.
    options.MaxBodyLogLength = 512;

    // Max bytes BFF will buffer from a backend response before failing the call
    // with InvalidResponse (default: 10 MiB). Applies to JSON/XML/form
    // deserialization. <= 0 disables the cap. See docs/raw-forwarding.md for the
    // separate raw-forward cap.
    options.MaxBackendResponseBytes = 10 * 1024 * 1024;

    // Raw-forward egress ceiling. Separate from MaxBackendResponseBytes because
    // raw forwards (file downloads, etc.) legitimately stream larger payloads
    // (default: 100 MiB). <= 0 disables the cap.
    options.MaxRawForwardResponseBytes = 100L * 1024 * 1024;

    // Max time between successive reads from a raw-forward backend before the
    // call is aborted (default: 30s). Defeats slow-loris backends that dribble
    // bytes to pin a BFF worker.
    options.RawForwardReadIdleTimeout = TimeSpan.FromSeconds(30);

    // Clock skew applied when deciding whether an access token is "near expiry"
    // and should be proactively refreshed (default: 60 seconds). Used by both
    // AccessTokenRefreshService and the ApiTokenService cache.
    options.TokenRefreshSkew = TimeSpan.FromSeconds(60);

    // Whether to log raw IdP error response bodies on token exchange/refresh/
    // revocation/introspection failures (default: false). Verbose IdPs frequently
    // echo the submitted refresh token / client secret / PII back inside the error
    // JSON - leave this off in production.
    options.LogIdpErrorBodies = false;

    // Max bytes of an IdP error response body that may be logged when
    // LogIdpErrorBodies is enabled (default: 512). Larger bodies are truncated.
    options.IdpErrorBodyMaxBytes = 512;

    // Default raw-forward header pass-through allow-list. By default the BFF strips
    // Cookie, Authorization, and X-Forwarded-* headers from raw-forwarded requests.
    // Add header names here to opt them back in globally (see docs/raw-forwarding.md).
    // options.DefaultRawForwardHeaderPassThrough.AllowedHeaders.Add("X-Foo");
});
```

Or bind from configuration:

```csharp
builder.Services.AddPortaCore(builder.Configuration);
```

```json
// appsettings.json
{
  "PortaCore": {
    "TrustedHosts": ["https://api.example.com"],
    "DefaultTimeout": "00:00:30",
    "MaxRetryAttempts": 3,
    "RefreshBackendTokenOn401": true,
    "RequireAuthorizationByDefault": true,
    "EnableTelemetry": true,
    "MaxBodyLogLength": 512,
    "MaxBackendResponseBytes": 10485760,
    "MaxRawForwardResponseBytes": 104857600,
    "RawForwardReadIdleTimeout": "00:00:30",
    "TokenRefreshSkew": "00:00:60",
    "LogIdpErrorBodies": false,
    "IdpErrorBodyMaxBytes": 512
  }
}
```

**What it registers:**
- Backend caller infrastructure (HttpClients with resilience)
- Backend auth handler registry with built-in handlers (`None`, `BearerToken`)
- Trusted host validation for secure token forwarding
- Transformer routing support

### AddPortaAuthentication() - OIDC Authentication (Opt-in)

Adds the full BFF OIDC pipeline: framework cookie + OpenIdConnect handlers, server-side ticket store, automatic refresh, RFC 7009 token revocation, and admin/back-channel session management. **Only call this if you need user authentication.**

```csharp
builder.Services.AddPortaAuthentication(builder.Configuration);
```

```json
// appsettings.json - section name defaults to "SessionAuthentication"
{
  "SessionAuthentication": {
    "Authority": "https://auth.example.com",
    "RequireHttpsMetadata": true,
    "ClientId": "my-porta",
    "ClientSecret": "secret",
    "Scope": "openid profile email api",
    "CookieName": "__Porta",
    "UsePkce": true,
    "QueryUserInfoEndpoint": true,
    "SessionTimeoutInMin": 60,
    "TokenExchangeStrategy": "default",
    "Cookie": {
      "SameSite": "Lax",
      "HttpOnly": true,
      "SecurePolicy": "Always",
      "ExpireTimeSpanMinutes": 60,
      "SlidingExpiration": false
    },
    "DataProtection": {
      "Enabled": true,
      "ApplicationName": "my-porta",
      "KeyLifetimeDays": 90
    },
    "Resilience": {
      "EnableRetry": true,
      "MaxRetryAttempts": 3,
      "InitialDelaySeconds": 1.0,
      "UseJitter": true,
      "EnableCircuitBreaker": true,
      "CircuitBreakerFailureRatio": 0.5,
      "CircuitBreakerSamplingDurationSeconds": 30.0,
      "CircuitBreakerMinimumThroughput": 10,
      "CircuitBreakerBreakDurationSeconds": 30.0,
      "RequestTimeoutSeconds": 10.0
    },
    "SessionKeys": {
      "Prefix": "porta"
    }
  }
}
```

Custom section name:

```csharp
builder.Services.AddPortaAuthentication(builder.Configuration, configSectionName: "MyAuth");
```

**Section name duality - `SessionAuthentication` vs `OidcAuth`.** `AddPortaAuthentication(IConfiguration)` defaults to the `"SessionAuthentication"` section and binds it onto `SessionAuthenticationConfiguration`. The `AddPortaOidcAuth(IConfiguration)` alias defaults to `"OidcAuth"` (the `OidcAuthOptions.SectionName` constant) and binds the same shape onto `OidcAuthOptions : SessionAuthenticationConfiguration`. Pick one section name in your `appsettings.json` and call the matching overload; the two are interchangeable, but the BFF will not read both. New code should prefer `AddPortaAuthentication` with the `SessionAuthentication` section.

**Legacy alias.** `AddPortaOidcAuth` (taking either `Action<OidcAuthOptions>` or `IConfiguration`) still works and forwards to `AddPortaAuthentication`. New code should call `AddPortaAuthentication` directly.

### Token refresh resilience - `SessionAuthentication.Resilience`

`Resilience` controls how the BFF retries and circuit-breaks the IdP token endpoint when refreshing access tokens via `ITokenRefreshService` / `IAccessTokenRefreshService`. The defaults are reasonable for most IdPs; tune only if your IdP is rate-limited, slow, or you've measured circuit-breaker false trips.

| Key | Default | Description |
|-----|---------|-------------|
| `EnableRetry` | `true` | Retry transient token-endpoint failures with exponential backoff. |
| `MaxRetryAttempts` | `3` | Max retry attempts. |
| `InitialDelaySeconds` | `1.0` | Base for exponential backoff (`delay = InitialDelaySeconds * 2^attempt`). |
| `UseJitter` | `true` | Add randomization to backoff to spread thundering-herd retries. |
| `EnableCircuitBreaker` | `true` | Open the breaker when the IdP is consistently failing. |
| `CircuitBreakerFailureRatio` | `0.5` | Failure ratio in the sampling window that trips the breaker. |
| `CircuitBreakerSamplingDurationSeconds` | `30.0` | Window over which `CircuitBreakerFailureRatio` is measured. |
| `CircuitBreakerMinimumThroughput` | `10` | Minimum requests in the window before the breaker may trip. |
| `CircuitBreakerBreakDurationSeconds` | `30.0` | How long the breaker stays open before transitioning to half-open. |
| `RequestTimeoutSeconds` | `10.0` | Per-request timeout on calls to the IdP token endpoint. |

### Session key namespace - `SessionAuthentication.SessionKeys`

`SessionKeys.Prefix` (default `"porta"`) is the prefix applied to every session-storage key the BFF writes - access/refresh/id tokens, expiry, API tokens, the auth context, and a `user.*` namespace. When two BFF instances share one Redis/Valkey and use the same prefix, their session writes collide. Set per-instance prefixes (e.g., `"customer-portal.porta"`, `"admin-porta"`) to namespace them.

The per-key suffixes (`AccessTokenKey`, `IdTokenKey`, `RefreshTokenKey`, `ExpiresAtKey`, `ApiAccessTokenKey`, `UserPrefix`, `AuthContextKey`) also have defaults and are rarely worth overriding - change them only if you're migrating from a custom layout.

### Backend service credentials - `BackendService`

`BackendServiceOptions` (section `"BackendService"`) configures the built-in `BasicAuth` and `TokenExchange` backend-auth handlers without requiring you to write a custom `IBackendAuthHandler`.

The `"BackendService"` section is bound automatically by the `AddPortaCore(IConfiguration)` overload. If you wire core options imperatively via `AddPortaCore(Action<PortaCoreOptions>)` instead, bind it yourself: `services.Configure<BackendServiceOptions>(builder.Configuration.GetSection(BackendServiceOptions.SectionName))`.

```json
{
  "BackendService": {
    "BaseUrl": "https://api.internal.example.com",
    "BasicAuth": { "Username": "bff", "Password": "..." },
    "Backends": {
      "PartnerApi": { "Username": "partner-bff", "Password": "..." }
    },
    "DefaultTokenExchangeAudience": "https://api.internal.example.com",
    "TokenExchangeAudiences": {
      "PartnerApi": "https://partner.example.com"
    }
  }
}
```

| Key | Description |
|-----|-------------|
| `BaseUrl` | Optional base URL for backend calls (consumer-facing convenience; not validated at startup). |
| `BasicAuth` | Default Basic credentials used by `BackendAuthPolicies.BasicAuth` when no per-backend entry matches. |
| `Backends` | Per-backend Basic credentials keyed by `BackendRequest.BackendName`. Case-insensitive. |
| `AllowGlobalBasicAuthFallback` | Default `false` (fail closed). When a request names a backend that has no matching `Backends` entry, the BasicAuth handler sends **no** `Authorization` header rather than reusing the global `BasicAuth` default (which could forward credentials meant for a different host). Set `true` for the legacy behaviour where such backends share the global default. Requests with no backend name always use `BasicAuth` regardless of this setting. |
| `DefaultTokenExchangeAudience` | Fallback audience for `BackendAuthPolicies.TokenExchange` when an endpoint doesn't supply one inline via `WithTokenExchange(audience)`. |
| `TokenExchangeAudiences` | Per-backend token-exchange audience override, keyed by `BackendRequest.BackendName`. |

When `BackendAuthPolicies.TokenExchange` is selected without an audience source (inline, default, or per-backend), Porta **fails fast at startup** for any endpoint mapped before the host starts. For cases the startup check can't see statically (e.g. a backend name rewritten at request time via `ModifyRequest`), the runtime backstop surfaces it as a server-side **configuration error (500-class)** - a missing audience is operator misconfiguration, not a user `401` credential rejection.

**What it registers:**
- ASP.NET Core `AddCookie()` + `AddOpenIdConnect()` - framework owns state/nonce/PKCE/code-exchange/id_token validation.
- `DistributedCacheTicketStore` as the cookie scheme's `SessionStore` - tokens live server-side, encrypted via `IDataProtector`. Cookie carries only an opaque ticket id.
- `AddDistributedMemoryCache()` as a fallback (Redis/Valkey wins via `TryAddSingleton` if registered).
- `AddDataProtection()` with the configured application name and key lifetime.
- `IAccessTokenRefreshService` - auto-refreshes near-expiry access tokens on each request, with per-user locking.
- Token services: `ITokenRefreshService`, `ITokenRevocationService`, `ITokenExchangeService`, `IApiTokenService`.
- `ISessionManagementService` for admin force-logout and back-channel logout flows.
- `OnTokenValidated` event handler that registers the session metadata + encrypted refresh token after successful sign-in.

### Registration Order

The recommended registration order is:

```csharp
// 1. Core services (always required)
builder.Services.AddPortaCore(options => { ... });

// 2. OIDC auth (if needed)
builder.Services.AddPortaAuthentication(builder.Configuration);

// 3. Custom auth handlers (if needed)
builder.Services.AddPortaAuthHandler<MyCustomHandler>();

// 4. Custom auth provider (if not using OIDC)
builder.Services.AddPortaAuthProvider<ApiKeyAuthProvider>();
```

## Production Configuration

Key settings that should be configured before a production deployment. The library only enforces a subset of these at startup (see [Startup Validation](#startup-validation) below); the rest are caller responsibilities surfaced here so they aren't missed.

| Setting | Environment Variable | Enforced? | Description |
|---------|---------------------|-----------|-------------|
| `SessionAuthentication:Authority` / `ClientId` / `ClientSecret` | `SessionAuthentication__Authority`, etc. | **Yes** - `IValidateOptions<SessionAuthenticationConfiguration>` with `ValidateOnStart`. | Required to start the app when `AddPortaAuthentication` is called. `Authority` must be an absolute http(s) URL. |
| `SessionAuthentication:RequireHttpsMetadata` | - | No (default `true`). | Leave `true` in production. Disabling allows the OIDC handler to fetch metadata over plain HTTP. |
| `PortaCore:TrustedHosts` (when any endpoint uses `.WithUserToken()`) | `PortaCore__TrustedHosts__0`, etc. | **Yes** - startup throws if a `WithUserToken()` backend host is not in the list. | See [Trusted Hosts](authentication.md#trusted-hosts). |
| `AllowedRedirectHosts` on `UseOidcLogin` / `UseOidcLogout` | - (configured in code, not via a config section) | Enforced at request time, not startup. | Per-call option on `OidcLoginOptions` / `OidcLogoutOptions`. When empty, only same-origin redirects are accepted; loopback is only accepted when `AllowLocalhost = true` (default `false`). External hosts are rejected with HTTP 400. There is no top-level `Logout:AllowedRedirectHosts` config section. |
| `ConnectionStrings:dataprotection-db` | `ConnectionStrings__dataprotection-db` | Indirect - `AddPortaDataProtectionWithEntityFrameworkStore` resolves the connection string and fails at startup when missing. | PostgreSQL connection for Data Protection keys. Required for HA - see [HA Deployment](ha-deployment.md). |
| HA prerequisites (shared `IDistributedCache`, persistent DP keys) | - | Soft - startup **warnings** `Porta/14500`/`14501`/`14502`/`14503`/`14504`/`14505` log when missing. | See [HA Deployment](ha-deployment.md). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `OTEL_EXPORTER_OTLP_ENDPOINT` | No - read by the OTel SDK. | OpenTelemetry collector endpoint. When set, metrics and traces are exported automatically. |
| `SessionAuthentication:SessionKeys:Prefix` | - | No. | Session key prefix for Redis. Default: `porta`. Change when sharing Redis with other BFF instances. |

### Multi-Replica / HA

Running more than one replica behind a load balancer requires a shared `IDistributedCache` (Redis/Valkey) and shared Data Protection key persistence. The defaults are dev-friendly; the auth pipeline emits a startup warning (event ids `14500`/`14501`) when an HA prerequisite is missing. Sticky sessions are **not** required.

See [HA Deployment](ha-deployment.md) for the full setup.

### Session timeouts - `SessionTimeoutInMin` vs `Cookie.ExpireTimeSpanMinutes`

The two settings look interchangeable but drive different clocks. Get them
both right or one expires while the other thinks the session is still alive.

| Setting | What it controls | Clock |
|---|---|---|
| `SessionAuthentication.SessionTimeoutInMin` | Server-side: distributed-cache ticket store TTL **and** ASP.NET Core `IdleTimeout` for `Session` middleware. Stops servicing requests for a session past this point. | Server wall-clock from last activity. |
| `SessionAuthentication.Cookie.ExpireTimeSpanMinutes` | Client-side: lifetime stamped into the cookie's `expires_at` token. The cookie auth handler refuses to authenticate principals whose stamp has passed. | Stamped at sign-in; checked on every request. |

Recommendation: set both to the **same value**. If you want sessions to extend
on activity, also set `SlidingExpiration = true` (default is `false`); the
server-side ticket and the cookie stamp both slide.

If you set only one:

- Server-side TTL shorter than cookie lifetime → cookie still valid, but ticket
  store has evicted the principal → ASP.NET Core treats the request as
  unauthenticated; the user sees a sudden sign-out partway through.
- Cookie lifetime shorter than server-side TTL → cookie self-expires while the
  server-side ticket lives on (wasted Redis space, but no functional impact).

### Cookie Security

`SessionAuthentication:Cookie:SecurePolicy` accepts `Always` (default), `SameAsRequest`, or `None`. `SameSite` accepts `Strict` (default), `Lax`, or `None`. Unknown values throw at startup - a typo like `"Allways"` used to silently fall back to a weaker policy; it now fails fast so the misconfiguration surfaces in CI/boot rather than after deploy.

For local development against HTTP, set `SecurePolicy` to `SameAsRequest` explicitly. Don't leave the default `Always` and run on HTTP - the auth cookie will be dropped by the browser.

### Startup Validation

The library validates a focused set of configuration values at startup and fails fast if any is wrong. Anything not in this list (e.g., `AllowedHosts`, a top-level `Logout` section, `BackendService:BaseUrl`) is **not** enforced by the BFF - treat those as host-app concerns.

When `AddPortaAuthentication` is called, `SessionAuthenticationConfigurationValidator` (registered with `ValidateOnStart`) rejects startup if:
- `SessionAuthentication.Authority` is missing or is not an absolute `http`/`https` URL
- `SessionAuthentication.ClientId` is missing
- `SessionAuthentication.ClientSecret` is missing
- `SessionAuthentication.SessionTimeoutInMin` is not positive
- `SessionAuthentication.Cookie.ExpireTimeSpanMinutes` is not positive
- `SessionAuthentication.Cookie.SecurePolicy` or `Cookie.SameSite` is not one of the recognized values (see [Cookie Security](#cookie-security))

Additional startup failures from other parts of the wiring:
- A transformer endpoint using `WithUserToken()` references a host outside `PortaCore.TrustedHosts` (thrown during endpoint mapping; see [Trusted Hosts](authentication.md#trusted-hosts)).
- `UseOidcBackChannelLogout` is called with `ValidateSignature`, `ValidateIssuer`, or `ValidateAudience` set to `false` outside the Development environment (throws `OptionsValidationException`).
- `UseOidcLogout(options.PerformGlobalLogout = true)` is called against an OIDC handler configured with `SaveTokens = false` - `id_token_hint` cannot be attached to the end-session request.
- `UseSessionAdmin` is called without a `RequirePolicy`, or the named policy is not registered.
- `AddPortaDataProtectionWithEntityFrameworkStore` cannot resolve its connection string.

### Logging

The library logs through `Microsoft.Extensions.Logging` under the `b17s.Porta.*` namespace. Configure log levels per category as you would for any ASP.NET Core app:

```json
{
  "Logging": {
    "LogLevel": {
      "b17s.Porta": "Information"
    }
  }
}
```
