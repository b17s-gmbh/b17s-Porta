using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Providers;
using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Services;
using b17s.Porta.Telemetry;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace b17s.Porta.Extensions;

/// <summary>
/// Primary extension methods for registering BFF services.
/// These are the main entry points for configuring the BFF library.
/// </summary>
public static class PortaServiceExtensions
{
    /// <summary>
    /// Adds core BFF services required for transformer-based API aggregation.
    /// This is the minimal setup needed for any BFF - no authentication included.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Optional action to configure BFF core options</param>
    /// <returns>The service collection for chaining</returns>
    /// <remarks>
    /// <para>
    /// This method registers:
    /// <list type="bullet">
    ///   <item>Backend caller infrastructure (HttpClients with resilience)</item>
    ///   <item>Transformer support services</item>
    ///   <item>Backend auth handler registry with built-in handlers (None, BearerToken, BasicAuth)</item>
    ///   <item>Trusted host validation for secure token forwarding</item>
    /// </list>
    /// </para>
    /// <para>
    /// For OIDC authentication, also call <see cref="AddPortaOidcAuth"/>.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Minimal setup - no auth
    /// builder.Services.AddPortaCore(options => {
    ///     options.DefaultTimeout = TimeSpan.FromSeconds(30);
    ///     options.EnableTelemetry = true;
    /// });
    ///
    /// // With trusted hosts for token forwarding
    /// builder.Services.AddPortaCore(options => {
    ///     options.TrustedHosts = ["https://api.example.com", "https://*.internal.example.com"];
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaCore(
        this IServiceCollection services,
        Action<PortaCoreOptions>? configureOptions = null)
    {
        // Configure core options through the standard options pipeline so consumer
        // Configure<PortaCoreOptions>(...) and PostConfigure<PortaCoreOptions>(...) calls
        // compose correctly. Using Options.Create(...) here would shadow the entire
        // pipeline and silently drop those calls.
        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }
        else
        {
            // Ensure IOptions<PortaCoreOptions> can still be resolved even when no
            // explicit configuration is supplied.
            services.AddOptions<PortaCoreOptions>();
        }

        // Materialize a snapshot for startup-time wiring below. Mutations to options
        // after this point still flow through IOptions<PortaCoreOptions> for runtime
        // consumers, but registrations captured by HttpClient/resilience must use
        // values fixed at registration.
        var coreOptions = new PortaCoreOptions();
        configureOptions?.Invoke(coreOptions);

        // Register HttpContextAccessor (required for token forwarding)
        services.AddHttpContextAccessor();

        // IApiTokenService is intentionally not registered here. The built-in
        // TokenExchangeAuthHandler takes it as a nullable dependency and throws a
        // clear 401-mapping error only on the token-exchange path that actually needs
        // it. Registering a stub factory would defeat that null handling and break
        // consumers that don't use auth. It is registered for real by
        // AddPortaAuthentication() / AddPortaOidcAuth().

        // IAuthenticationProvider resolves through CompositeAuthenticationProvider.
        // Each registration extension (AddPortaOidcAuth, AddReferenceTokenAuthentication,
        // AddPortaJwtAuthentication, AddPortaAuthProvider<T>) adds an
        // IAuthenticationProviderRegistration entry; the composite tries them in
        // registration order on each request. Consumers can combine credential types
        // (session + JWT + reference token + custom) on the same endpoints.
        services.TryAddScoped<IAuthenticationProvider>(sp =>
        {
            var providers = sp.GetServices<IAuthenticationProviderRegistration>()
                .Select(r => r.Provider)
                .ToList();
            if (providers.Count == 0)
            {
                throw new InvalidOperationException(
                    "No authentication provider registered. " +
                    "Call AddPortaOidcAuth() for OIDC authentication or AddPortaAuthProvider<T>() for custom authentication.");
            }

            var logger = sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<CompositeAuthenticationProvider>>();
            return new CompositeAuthenticationProvider(providers, logger);
        });

        // Register HttpClient without retries (default)
        services.AddHttpClient(BackendCaller.HttpClientName, client =>
        {
            client.Timeout = coreOptions.DefaultTimeout;
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        })
        // Auto-redirect is disabled: TrustedHostValidator runs only at startup against
        // the configured UrlTemplate. A backend returning `302 Location: https://attacker/...`
        // would otherwise cause the client to follow without re-validating, leaking any
        // custom headers added by IBackendAuthHandler (X-Api-Key, HMAC signatures, etc.) -
        // .NET only strips Authorization on cross-origin redirects.
        .ConfigurePrimaryHttpMessageHandler(() => new System.Net.Http.SocketsHttpHandler
        {
            AllowAutoRedirect = false,
        });

        // Register HttpClient with retries (used when EnableRetries = true)
        services.AddHttpClient(BackendCaller.HttpClientNameWithRetries, client =>
        {
            client.Timeout = coreOptions.DefaultTimeout;
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        })
        .ConfigurePrimaryHttpMessageHandler(() => new System.Net.Http.SocketsHttpHandler
        {
            AllowAutoRedirect = false,
        })
        .AddStandardResilienceHandler(resilience =>
        {
            resilience.AttemptTimeout.Timeout = coreOptions.DefaultTimeout;
            resilience.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(coreOptions.DefaultTimeout.TotalSeconds * 2);
            resilience.Retry.MaxRetryAttempts = coreOptions.MaxRetryAttempts;
            // Circuit breaker sampling duration must be at least 2x the attempt timeout
            resilience.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(coreOptions.DefaultTimeout.TotalSeconds * 2.5);
        });

        // Register built-in backend auth handlers as IBackendAuthHandler. Consumers add
        // custom handlers via AddPortaAuthHandler<T> which appends to the same DI
        // enumeration. The registry is composed from the enumerable at resolve time,
        // so the order of registration calls no longer matters and duplicate calls
        // are additive instead of destructive.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBackendAuthHandler, NoneAuthHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBackendAuthHandler, BearerTokenAuthHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBackendAuthHandler, BasicAuthHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBackendAuthHandler, TokenExchangeAuthHandler>());

        services.TryAddSingleton<IBackendAuthHandlerRegistry>(sp =>
        {
            var registry = new BackendAuthHandlerRegistry();
            foreach (var handler in sp.GetServices<IBackendAuthHandler>())
            {
                registry.Register(handler);
            }
            return registry;
        });

        // Register the content serializer used by BackendCaller for JSON/XML/form-encoded payloads.
        // TryAdd so callers can swap in a custom IContentSerializer.
        services.TryAddSingleton<IContentSerializer, ContentSerializer>();

        // Default backend error mapper: maps backend 401/403 to 502 so the client doesn't
        // sign out the user when *backend* credentials are wrong. Use TryAdd so consumers
        // can register a custom IBackendErrorMapper (e.g. PassThroughBackendErrorMapper).
        services.TryAddSingleton<IBackendErrorMapper, DefaultBackendErrorMapper>();

        services.AddScoped<IBackendCaller, BackendCaller>();

        // Fail fast at startup if token-exchange audiences are configured but the token-exchange
        // dependency (IApiTokenService) was never registered - otherwise it only surfaces as a
        // request-time ConfigurationError on the first token-exchange route.
        services.AddHostedService<TokenExchangeConfigurationStartupCheck>();

        // Open-generic registration so MapPassThrough<TResponse>() can resolve a
        // synthetic BackendForwardingTransformer<TResponse> for any TResponse.
        services.AddTransient(typeof(BackendForwardingTransformer<>));

        // The zero-code MapRawForward() overloads default to
        // RawForwardEndpointBuilder<DefaultRawForwardTransformer>, which resolves the
        // transformer from DI at request time. Register the default here so the
        // documented no-transformer proxy examples work without the consumer having to
        // call AddRawForwardTransformer<DefaultRawForwardTransformer>() themselves.
        // TryAdd so a consumer can still override the default registration if desired.
        services.TryAddTransient<DefaultRawForwardTransformer>();

        // Register trusted host validator for WithUserToken() validation at startup
        services.AddSingleton<ITrustedHostValidator, TrustedHostValidator>();

        // Register the matcher policy for When() predicate-based conditional routing
        services.AddSingleton<MatcherPolicy, WhenPredicateMatcherPolicy>();

        // Register BFF metrics for telemetry (always registered as BackendCaller depends on it)
        services.AddSingleton<PortaMetrics>();

        // Default TimeProvider so internal services that take TimeProvider as a
        // constructor parameter resolve to wall-clock unless the consumer
        // (typically a test host) has already registered FakeTimeProvider.
        services.TryAddSingleton(TimeProvider.System);

        // Authorization services. Porta is not authorization-agnostic: PortaCoreOptions
        // defaults RequireAuthorizationByDefault = true, so every transformer / pass-through
        // endpoint applies RequireAuthorization() unless explicitly AllowAnonymous, and the
        // OIDC endpoints / SessionAdminMiddleware resolve IAuthorizationService directly.
        // Owning this registration keeps the secure default self-consistent so consumers
        // don't have to remember a separate AddAuthorization() call just to make Porta's
        // own behavior work. AddAuthorization is idempotent (TryAdd-based) and additive,
        // so a consumer's later AddAuthorization(options => options.AddPolicy(...)) and
        // custom IAuthorizationPolicyProvider registrations still compose normally.
        services.AddAuthorization();

        return services;
    }

    /// <summary>
    /// Adds core BFF services with configuration binding from appsettings.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">The configuration root</param>
    /// <param name="sectionName">The configuration section name (default: "PortaCore")</param>
    /// <returns>The service collection for chaining</returns>
    /// <example>
    /// <code>
    /// // In appsettings.json:
    /// // "PortaCore": {
    /// //   "TrustedHosts": ["https://api.example.com"],
    /// //   "DefaultTimeout": "00:00:30"
    /// // }
    ///
    /// builder.Services.AddPortaCore(builder.Configuration);
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaCore(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = PortaCoreOptions.SectionName)
        => services.AddPortaCore(opt => configuration.GetSection(sectionName).Bind(opt));

    /// <summary>
    /// Adds OIDC authentication with session-based token storage.
    /// This is an opt-in addition to <see cref="AddPortaCore"/>.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Action to configure OIDC options</param>
    /// <returns>The service collection for chaining</returns>
    /// <remarks>
    /// <para>
    /// This method registers:
    /// <list type="bullet">
    ///   <item>Session-based authentication with cookie support</item>
    ///   <item>Token refresh, exchange, and revocation services</item>
    ///   <item>OIDC discovery service</item>
    ///   <item>Session management services</item>
    ///   <item>Data Protection for token encryption at rest</item>
    ///   <item>Logout services</item>
    /// </list>
    /// </para>
    /// <para>
    /// Requires a distributed cache (Redis/Valkey) for session storage in production.
    /// Use <c>builder.AddRedisDistributedCache("cache")</c> with Aspire or
    /// <c>services.AddStackExchangeRedisCache()</c> manually.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Services.AddPortaCore();
    /// builder.Services.AddPortaOidcAuth(options => {
    ///     options.Authority = "https://auth.example.com";
    ///     options.ClientId = "my-porta";
    ///     options.ClientSecret = builder.Configuration["Oidc:ClientSecret"];
    ///     options.Scope = "openid profile email api";
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaOidcAuth(
        this IServiceCollection services,
        Action<OidcAuthOptions> configureOptions)
    {
        // Single source of truth: materialise the caller's lambda once into a snapshot,
        // then project it into both option types. Re-invoking the lambda per
        // IOptions resolution would fire any side effects (logging, secrets fetches)
        // repeatedly and risk drift between the two registrations.
        var snapshot = new OidcAuthOptions();
        configureOptions(snapshot);

        services.Configure<OidcAuthOptions>(opt => CopyOptions(snapshot, opt));

        // Validate OidcAuthOptions at host start so a misconfigured BFF fails on
        // boot rather than on the first OIDC redirect.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                Microsoft.Extensions.Options.IValidateOptions<OidcAuthOptions>,
                OidcAuthOptionsValidator>());
        services.AddOptions<OidcAuthOptions>().ValidateOnStart();

        // Pass the copy action to AddPortaAuthentication so it registers the Configure<>
        // and importantly populates the startup-time config snapshot used for DI wiring.
        services.AddPortaAuthentication(opt => CopyOptions(snapshot, opt));

        return services;
    }

    /// <summary>
    /// Adds OIDC authentication with configuration binding from appsettings.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">The configuration root</param>
    /// <param name="sectionName">The configuration section name (default: "OidcAuth")</param>
    /// <returns>The service collection for chaining</returns>
    /// <example>
    /// <code>
    /// // In appsettings.json:
    /// // "OidcAuth": {
    /// //   "Authority": "https://auth.example.com",
    /// //   "ClientId": "my-porta",
    /// //   "ClientSecret": "secret",
    /// //   "Scope": "openid profile email"
    /// // }
    ///
    /// builder.Services.AddPortaCore();
    /// builder.Services.AddPortaOidcAuth(builder.Configuration);
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaOidcAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = OidcAuthOptions.SectionName)
    {
        var snapshot = new OidcAuthOptions();
        configuration.GetSection(sectionName).Bind(snapshot);

        // Route through the Action<> overload so both option types are registered
        // from a single source. The Action<> overload owns all Configure<> calls.
        return services.AddPortaOidcAuth(opt => CopyOptions(snapshot, opt));
    }

    /// <summary>
    /// Registers a custom backend authentication handler.
    /// </summary>
    /// <typeparam name="THandler">The handler type implementing <see cref="IBackendAuthHandler"/></typeparam>
    /// <param name="services">The service collection</param>
    /// <returns>The service collection for chaining</returns>
    /// <remarks>
    /// <para>
    /// Backend auth handlers are used to authenticate requests to backend services.
    /// Each handler implements a specific authentication policy (e.g., API key, HMAC, OAuth client credentials).
    /// </para>
    /// <para>
    /// The handler's <see cref="IBackendAuthHandler.PolicyName"/> is used to reference it in endpoint configuration:
    /// <c>.WithBackendAuth("PolicyName")</c>
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Custom handler implementation
    /// public class HmacAuthHandler : IBackendAuthHandler
    /// {
    ///     public string PolicyName => "HmacAuth";
    ///
    ///     public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
    ///     {
    ///         var signature = ComputeHmacSignature(request);
    ///         request.Headers.Add("X-Signature", signature);
    ///         request.Headers.Add("X-Timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
    ///         return Task.CompletedTask;
    ///     }
    /// }
    ///
    /// // Registration
    /// builder.Services.AddPortaCore();
    /// builder.Services.AddPortaAuthHandler&lt;HmacAuthHandler&gt;();
    ///
    /// // Usage in endpoint
    /// app.MapTransformer&lt;MyTransformer, Response&gt;()
    ///    .FromRoute("GET", "/api/data")
    ///    .ToBackend("GET", "https://partner-api.example.com/data")
    ///    .WithBackendAuth("HmacAuth")
    ///    .Build();
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaAuthHandler<THandler>(this IServiceCollection services)
        where THandler : class, IBackendAuthHandler
    {
        // Append to the IBackendAuthHandler enumeration. The registry built in
        // AddPortaCore consumes IEnumerable<IBackendAuthHandler> at resolve time, so
        // multiple calls (and mixing of typed/factory variants) compose additively.
        // TryAddEnumerable de-duplicates by implementation type, so calling this
        // twice with the same THandler is a no-op rather than overwriting.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBackendAuthHandler, THandler>());
        return services;
    }

    /// <summary>
    /// Registers a custom backend authentication handler using a factory function.
    /// </summary>
    /// <typeparam name="THandler">The handler type implementing <see cref="IBackendAuthHandler"/></typeparam>
    /// <param name="services">The service collection</param>
    /// <param name="implementationFactory">Factory function to create the handler instance</param>
    /// <returns>The service collection for chaining</returns>
    /// <example>
    /// <code>
    /// builder.Services.AddPortaAuthHandler&lt;ApiKeyAuthHandler&gt;(sp =>
    ///     new ApiKeyAuthHandler(
    ///         sp.GetRequiredService&lt;IConfiguration&gt;()["ApiKeys:PartnerApi"]));
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaAuthHandler<THandler>(
        this IServiceCollection services,
        Func<IServiceProvider, THandler> implementationFactory)
        where THandler : class, IBackendAuthHandler
    {
        // Append to the IBackendAuthHandler enumeration via factory. TryAddEnumerable
        // de-duplicates by implementation type, so the same THandler is only added
        // once even across mixed typed/factory calls.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IBackendAuthHandler, THandler>(implementationFactory));
        return services;
    }

    /// <summary>
    /// Registers multiple custom backend authentication handlers at once.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="handlerTypes">The handler types implementing <see cref="IBackendAuthHandler"/></param>
    /// <returns>The service collection for chaining</returns>
    /// <example>
    /// <code>
    /// builder.Services.AddPortaAuthHandlers(
    ///     typeof(HmacAuthHandler),
    ///     typeof(ApiKeyAuthHandler),
    ///     typeof(ClientCredentialsAuthHandler));
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaAuthHandlers(
        this IServiceCollection services,
        params Type[] handlerTypes)
    {
        // Validate all types implement IBackendAuthHandler, then append each to the
        // IBackendAuthHandler enumeration. TryAddEnumerable de-duplicates by
        // implementation type, so calling this twice with overlapping types is safe.
        foreach (var type in handlerTypes)
        {
            if (!typeof(IBackendAuthHandler).IsAssignableFrom(type))
            {
                throw new ArgumentException(
                    $"Type {type.Name} does not implement IBackendAuthHandler",
                    nameof(handlerTypes));
            }

            services.TryAddEnumerable(
                ServiceDescriptor.Singleton(typeof(IBackendAuthHandler), type));
        }

        return services;
    }

    #region Private Helper Methods

    private static void CopyOptions(OidcAuthOptions source, SessionAuthenticationConfiguration target)
    {
        target.CookieName = source.CookieName;
        target.Scope = source.Scope;
        target.Authority = source.Authority;
        target.RequireHttpsMetadata = source.RequireHttpsMetadata;
        target.ClientId = source.ClientId;
        target.ClientSecret = source.ClientSecret;
        target.UsePkce = source.UsePkce;
        target.SessionTimeoutInMin = source.SessionTimeoutInMin;
        target.TokenExchangeStrategy = source.TokenExchangeStrategy;
        target.QueryUserInfoEndpoint = source.QueryUserInfoEndpoint;
        // Deep-copy the mutable sub-objects so the two registered options types
        // (IOptions<OidcAuthOptions> and IOptions<SessionAuthenticationConfiguration>)
        // do not alias the same instances. Aliasing would let a PostConfigure
        // mutation on one silently affect the other, defeating the single-source-of-truth
        // intent of this copy.
        target.Cookie = source.Cookie.Clone();
        target.Resilience = source.Resilience.Clone();
        target.DataProtection = source.DataProtection.Clone();
        target.SessionKeys = source.SessionKeys.Clone();
    }

    private static void CopyOptions(OidcAuthOptions source, OidcAuthOptions target)
        => CopyOptions(source, (SessionAuthenticationConfiguration)target);

    #endregion
}
