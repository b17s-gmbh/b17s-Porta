# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.2] - 2026-06-14
### Added
- BFF Transformer (TransformerBase, PassThroughTransformer, AuthenticatedTransformer, MultiBackendTransformer, AggregatingTransformer)
- Multi-backend aggregation (AggregatingTransformer)
- Zero-code pass-through (PassThroughTransformer)
- Per-backend authentication policies (None, BasicAuth, BearerToken, TokenExchange)
- Fluent endpoint builder (WithAuth, WithTimeout, WithRetries, WithTokenExchange)
- Startup configuration validation
- Multiple auth providers
- Token lifecycle
- Session administration
- OIDC discovery
- Raw forwarding
- GraphQL support
- SSRF guard for token forwarding 
- Open-redirect protection
- Signed, time-limited return-URL tokens
- Constant-time Basic auth
- Secret-classified log redaction
- HA-ready, no sticky sessions
- Data Protection persistence
- Resilience
- OpenTelemetry
- Runnable demo
- UnitTests
