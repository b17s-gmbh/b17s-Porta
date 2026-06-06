using b17s.Porta.Transformers;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Exercises every branch of <see cref="EndpointAuthorizationValidator"/>. The validator
/// is the startup-time gate that prevents a misconfigured endpoint from silently
/// forwarding (or failing to forward) user credentials to a backend — a class of bug
/// you only catch at first request without this check. Each "requires identity" source
/// (token exchange, backend-auth policy that names a user, <c>ForwardUserToken</c>, and
/// the <see cref="RequiresAuthenticationAttribute"/>) needs a dedicated assertion so a
/// future refactor cannot accidentally drop one without breaking a test.
/// </summary>
public sealed class EndpointAuthorizationValidatorTests
{
    private sealed class FakeAuthHandler(string policyName) : IBackendAuthHandler
    {
        public string PolicyName { get; } = policyName;
        public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context) => Task.CompletedTask;
    }

    private static BackendAuthHandlerRegistry RegistryWith(params string[] policies)
    {
        var registry = new BackendAuthHandlerRegistry();
        foreach (var p in policies)
        {
            registry.Register(new FakeAuthHandler(p));
        }
        return registry;
    }

    [RequiresAuthentication]
    private sealed class AuthRequiredTransformer { }

    private sealed class AnonymousTransformer { }

    public sealed class ValidatePolicyRegistered
    {
        [Fact]
        public void NullPolicy_NoOp()
        {
            // Null is the documented "no backend auth policy" sentinel; must not throw.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: null,
                    registry: new BackendAuthHandlerRegistry(),
                    context: "endpoint '/api/x'"));

            Assert.Null(ex);
        }

        [Fact]
        public void EmptyPolicy_NoOp()
        {
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: "",
                    registry: new BackendAuthHandlerRegistry(),
                    context: "endpoint '/api/x'"));

            Assert.Null(ex);
        }

        [Fact]
        public void NullRegistry_NoOp()
        {
            // No registry means we can't validate — the caller may be in a context where
            // the registry isn't wired (e.g. tests). The validator must not throw a NRE.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: "BasicAuth",
                    registry: null,
                    context: "endpoint '/api/x'"));

            Assert.Null(ex);
        }

        [Fact]
        public void RegisteredPolicy_NoOp()
        {
            var registry = RegistryWith("BasicAuth", "BearerToken");

            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: "BasicAuth",
                    registry: registry,
                    context: "endpoint '/api/x'"));

            Assert.Null(ex);
        }

        [Fact]
        public void UnregisteredPolicy_ThrowsWithRegisteredList()
        {
            // The error message lists the registered policies so the user can spot a typo.
            // (The registry itself is case-insensitive, so the typo must be a real typo —
            // case alone does not register as unknown.)
            var registry = RegistryWith("BasicAuth", "BearerToken");

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: "BasiqAuth",
                    registry: registry,
                    context: "endpoint '/api/x'"));

            Assert.Contains("BasiqAuth", ex.Message);
            Assert.Contains("endpoint '/api/x'", ex.Message);
            Assert.Contains("BasicAuth", ex.Message);
            Assert.Contains("BearerToken", ex.Message);
        }

        [Fact]
        public void RegisteredPolicy_CaseInsensitive_NoOp()
        {
            // The registry is case-insensitive — "BasicAuth" and "basicauth" resolve to the
            // same handler. Lock this in so a future refactor doesn't quietly tighten the
            // comparison and break existing configs.
            var registry = RegistryWith("BasicAuth");

            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: "basicauth",
                    registry: registry,
                    context: "endpoint '/api/x'"));

            Assert.Null(ex);
        }
    }

    public sealed class Validate
    {
        [Fact]
        public void NoIdentitySources_NoAuthRequired_NoOp()
        {
            // Pure happy path: nothing needs identity, endpoint allows anonymous — fine.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/public",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false));

            Assert.Null(ex);
        }

        [Fact]
        public void IdentityRequired_AuthEnabled_NoOp()
        {
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/orders",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: true,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken)));

            Assert.Null(ex);
        }

        [Fact]
        public void TokenExchange_WithoutRequireAuth_Throws()
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/orders",
                    backendAuthPolicy: null,
                    useTokenExchange: true,
                    tokenExchangeAudience: "orders-api",
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false));

            Assert.Contains("/api/orders", ex.Message);
            Assert.Contains("AllowAnonymous", ex.Message);
            Assert.Contains("orders-api", ex.Message);
        }

        [Fact]
        public void BearerTokenPolicy_WithoutRequireAuth_Throws()
        {
            // BearerToken at the top-level policy means "forward the user's token". An
            // anonymous endpoint here would forward nothing — silent breakage instead of
            // an early loud failure.
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/me",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken)));

            Assert.Contains(BackendAuthPolicies.BearerToken, ex.Message);
        }

        [Fact]
        public void NonIdentityPolicy_WithoutRequireAuth_NoOp()
        {
            // BasicAuth uses the BFF's own credentials, not the user's — so AllowAnonymous
            // is fine for it. This is the canonical "anonymous endpoint hitting a backend
            // with shared creds" case.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/catalog",
                    backendAuthPolicy: BackendAuthPolicies.BasicAuth,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BasicAuth)));

            Assert.Null(ex);
        }

        [Fact]
        public void TransformerWithRequiresAuthentication_WithoutRequireAuth_Throws()
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/secure",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    transformerType: typeof(AuthRequiredTransformer)));

            Assert.Contains(nameof(AuthRequiredTransformer), ex.Message);
            Assert.Contains("RequiresAuthentication", ex.Message);
        }

        [Fact]
        public void TransformerWithoutAttribute_NoOp()
        {
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/secure",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    transformerType: typeof(AnonymousTransformer)));

            Assert.Null(ex);
        }

        [Fact]
        public void NamedBackend_ForwardUserToken_WithoutRequireAuth_Throws()
        {
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "user-data",
                Method = "GET",
                UrlTemplate = "https://users.test/api",
                ForwardUserToken = true,
            });

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: false));

            Assert.Contains("user-data", ex.Message);
        }

        [Fact]
        public void NamedBackend_TokenExchange_WithoutRequireAuth_Throws()
        {
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "orders",
                Method = "GET",
                UrlTemplate = "https://orders.test/api",
                UseTokenExchange = true,
                TokenExchangeAudience = "orders-api",
            });

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: false));

            Assert.Contains("orders", ex.Message);
        }

        [Fact]
        public void NamedBackend_BearerTokenPolicy_WithoutRequireAuth_Throws()
        {
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "me",
                Method = "GET",
                UrlTemplate = "https://me.test/api",
                BackendAuthPolicy = BackendAuthPolicies.BearerToken,
            });

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken)));

            Assert.Contains("me", ex.Message);
        }

        [Fact]
        public void NamedBackend_NonIdentityPolicy_WithoutRequireAuth_NoOp()
        {
            // Belt-and-braces: a named backend that uses BasicAuth (BFF creds) shouldn't trip
            // the validator regardless of the endpoint's anonymous flag.
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "catalog",
                Method = "GET",
                UrlTemplate = "https://catalog.test/api",
                BackendAuthPolicy = BackendAuthPolicies.BasicAuth,
            });

            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/things",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BasicAuth)));

            Assert.Null(ex);
        }

        [Fact]
        public void UnknownTopLevelPolicy_Throws_BeforeIdentityChecks()
        {
            // Policy validation runs first — even if other checks would also fire, the user
            // hears about the typo immediately rather than chasing a misleading second
            // error.
            var registry = RegistryWith(BackendAuthPolicies.BasicAuth);

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/x",
                    backendAuthPolicy: "BasiqAuth",
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: true,
                    authHandlerRegistry: registry));

            Assert.Contains("BasiqAuth", ex.Message);
            Assert.Contains("BasicAuth", ex.Message);
        }

        [Fact]
        public void UnknownNamedBackendPolicy_Throws()
        {
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "orders",
                Method = "GET",
                UrlTemplate = "https://orders.test/api",
                BackendAuthPolicy = "DoesNotExist",
            });
            var registry = RegistryWith(BackendAuthPolicies.BasicAuth);

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/x",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: true,
                    authHandlerRegistry: registry));

            Assert.Contains("DoesNotExist", ex.Message);
            Assert.Contains("orders", ex.Message);
        }

        [Fact]
        public void MultipleIdentitySources_AllReportedInMessage()
        {
            // The combined error message lists every source so the developer can fix them
            // in one round-trip instead of one per recompile.
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "orders",
                Method = "GET",
                UrlTemplate = "https://orders.test/api",
                ForwardUserToken = true,
            });

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    useTokenExchange: true,
                    tokenExchangeAudience: "orders-api",
                    namedBackends: backends,
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken),
                    transformerType: typeof(AuthRequiredTransformer)));

            Assert.Contains(BackendAuthPolicies.BearerToken, ex.Message);
            Assert.Contains("orders-api", ex.Message);
            Assert.Contains("orders", ex.Message);
            Assert.Contains(nameof(AuthRequiredTransformer), ex.Message);
        }
    }
}
