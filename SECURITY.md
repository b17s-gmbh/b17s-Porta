# Security Policy

Thank you for helping keep `b17s.Porta` and its users safe.

## Reporting a vulnerability

**Please do not file a public GitHub issue, discussion, pull request, or social-media post for suspected security vulnerabilities.**

Use one of these private channels instead:

**Preferred - GitHub Private Vulnerability Reporting:** open a report at
   <https://github.com/b17s-gmbh/b17s-Porta/security/advisories/new>.
   This routes directly to the maintainers and lets us collaborate on a fix and an embargoed advisory before disclosure.

When you report, please include as much of the following as you can:

- A clear description of the issue and the impact you believe it has.
- The affected version(s) - package version, commit SHA, or branch.
- A minimal reproduction: configuration snippet, request, or test case.
- Any logs or stack traces (please redact tokens, cookies, and PII before sending).
- Whether you have already disclosed this to anyone else, and any public references.
- How you'd like to be credited in the advisory, if at all.

We will acknowledge receipt within **10 business days** and aim to provide an initial assessment within **10 business days**. Critical issues that allow account takeover, unauthenticated bypass of authorization, or remote code execution are prioritized over everything else.

## Coordinated disclosure

We follow a coordinated-disclosure model:

- We will work with you on a fix and an advisory in private.
- We will request a CVE through GitHub's advisory workflow for any vulnerability that warrants one.
- We will not publicly disclose details before a fix is available, unless the issue is already public, actively exploited, or you and we agree disclosure is in users' best interest.
- We are happy to credit reporters in the advisory. Let us know how you'd like to be named (or if you prefer to remain anonymous).
- We do not currently run a paid bug bounty program.

## Supported versions

`b17s.Porta` follows [SemVer](https://semver.org/). Security fixes are issued for:

| Version | Supported              |
| ------- | ---------------------- |
| 1.x     | :white_check_mark: latest minor |
| < 1.0   | :x: pre-release, unsupported |

Security fixes will normally land in the latest minor of the latest major; we will backport to the previous minor on a case-by-case basis when the upgrade path is non-trivial.

## Scope

In scope:

- The `b17s.Porta` NuGet package - auth, OIDC middleware, token services, transformers, raw forwarding, session management, telemetry.
- Default options and behavior documented in `README.md` and `docs/`.
- The package's published symbols and SourceLink metadata.

Out of scope (please do not report these as vulnerabilities):

- Misconfiguration of consuming applications (e.g., disabling `ValidateSignature` outside Development, exposing the admin endpoint without an admin policy, running without TLS, deploying without a reverse proxy in a topology the README calls out as edge-only).
- Vulnerabilities in third-party packages we depend on - please report those upstream. We will track and update once they are fixed.
- Denial-of-service from clients we explicitly trust per configuration (e.g., a malicious backend you've added to `TrustedHosts`).
- Findings that require physical or admin access to the host running the BFF.

## Deployment posture

`b17s.Porta` is designed for a typical BFF topology: **deployed behind a hardened reverse proxy, serving a first-party web/mobile front-end**. The library has been reviewed and is considered safe for non-edge scenarios — standard OIDC flows, session-based auth, reference tokens, and backend aggregation behind a trusted reverse proxy. If you operate at the edge — directly exposed to the public internet, in a shared-host environment, or handling untrusted tenant traffic, or otherwise outside a typical web-app deployment — review the threat model and add hardening at the proxy layer or in the middleware pipeline (request size limits, method/path enforcement, forwarded-header configuration, stricter redirect-URI validation, custom CSRF/anti-abuse controls). Missing edge hardening in the library defaults is a documented limitation, not a vulnerability.

Porta is also pre-1.0 and has not yet been battle-hardened in production at scale. Pin a known version, and review changelogs before upgrading.

## Sensitive data in logs

**Treat Porta's log stream as a Secret-classified data source.** Unhandled exception traces from the auth code path, request-correlation IDs, user identifiers, and anything your own logging pipeline adds upstream of Porta are all outside this library's control. Restrict access, ship to a sink with appropriate access controls and retention, and avoid forwarding the stream to third-party log aggregators or chat channels without redaction.

Session IDs are credential-equivalent and are **never** logged raw — they appear only as a non-reversible `sid:` fingerprint. User identifiers (`email`, the OIDC `sub` claim) are PII rather than Secrets and **are** logged raw to keep operational debugging tractable; each is accompanied by a stable `email:` / `sub:` fingerprint so log lines can be correlated even where the raw value is later scrubbed. This is why the log stream as a whole is Secret-classified: protect it accordingly.

By default, Porta redacts IdP error bodies and logs only the HTTP status when token refresh, exchange, introspection, or revocation fails. If you set `PortaCore:LogIdpErrorBodies=true` for debugging, those bodies are written at Debug truncated to `IdpErrorBodyMaxBytes` — and verbose IdPs (Keycloak, IdentityServer in dev mode, etc.) frequently echo the submitted refresh token, client secret, or PII back inside that JSON. Enable it only on a single instance, only temporarily, and only when you accept the risk.

## Known security-relevant configuration

These are *intended* behaviors that operators should be aware of when threat-modeling their deployment:

- **Reference tokens are the recommended default**; JWT inbound is opt-in via `AddPortaJwtAuthentication`.
- **Endpoints require authorization by default** (`PortaCoreOptions.RequireAuthorizationByDefault = true`).
- **The admin session endpoints are opt-in** and must be gated by an admin authorization policy you provide.
- **Distributed Data Protection key encryption is required in non-Development** - startup will refuse to boot a multi-replica HA configuration without it, unless explicitly acknowledged.
- **`AllowAutoRedirect` is disabled** on the backend `HttpClient` to prevent leaking custom auth headers on cross-origin redirects.
- **Raw-forward DoS caps are response-direction only.** `MaxRawForwardResponseBytes` and `RawForwardReadIdleTimeout` bound the backend→client stream. The client→backend (upload) direction has no per-endpoint cap by design; over-large and slow-loris uploads are delegated to Kestrel's global `MaxRequestBodySize` / `MinRequestBodyDataRate` / `RequestHeadersTimeout`, which operators should configure. See [`docs/raw-forwarding.md`](docs/raw-forwarding.md#request-direction--kestrel-reliance).
- See [`docs/authentication.md`](docs/authentication.md) and [`docs/ha-deployment.md`](docs/ha-deployment.md) for the full picture.
