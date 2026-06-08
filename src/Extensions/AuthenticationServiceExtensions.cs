using System.Security.Claims;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Providers;
using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Services;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace b17s.Porta.Extensions;

/// <summary>
/// Extension methods for registering BFF authentication services.
/// </summary>
public static class AuthenticationServiceExtensions
{
    /// <summary>
    /// Name of the resilient <see cref="HttpClient"/> used by all token-flow services
    /// (refresh, exchange, revocation) and OIDC discovery. Registered in
    /// <see cref="AddTokenServices"/> with <c>AddStandardResilienceHandler</c>; any
    /// consumer that fetches via <see cref="IHttpClientFactory"/> must use this name
    /// to inherit timeout/retry/circuit-breaker policy.
    /// </summary>
    public const string TokenHttpClientName = "Porta.TokenClient";

    /// <summary>
    /// Adds the full BFF authentication pipeline:
    /// <list type="bullet">
    ///   <item>ASP.NET Core Cookie + OpenIdConnect schemes (the framework handles state/nonce/PKCE/code-exchange/id_token validation).</item>
    ///   <item>Server-side ticket storage via <see cref="DistributedCacheTicketStore"/> - cookies carry only an opaque ticket id; tokens live in <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>, encrypted via <see cref="IDataProtector"/>.</item>
    ///   <item>Custom token services: refresh, revocation (RFC 7009), exchange (RFC 8693), API token caching.</item>
    ///   <item>Auto-refresh of access tokens before expiry via <see cref="IAccessTokenRefreshService"/>.</item>
    ///   <item>Session management (admin force-logout, back-channel logout).</item>
    /// </list>
    /// Requires an <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/> registration. In production
    /// use Redis/Valkey via Aspire (<c>builder.AddRedisDistributedCache("cache")</c>) or
    /// <c>services.AddStackExchangeRedisCache()</c>. For development falls back to an
    /// in-memory cache via <c>AddDistributedMemoryCache()</c>.
    /// </summary>
    public static IServiceCollection AddPortaAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        string configSectionName = "SessionAuthentication")
    {
        services.Configure<SessionAuthenticationConfiguration>(configuration.GetSection(configSectionName));

        return services.AddPortaAuthenticationCore();
    }

    /// <summary>
    /// Adds the full BFF authentication pipeline using an action to configure
    /// <see cref="SessionAuthenticationConfiguration"/>. Use this overload when callers
    /// want to bind options imperatively (or have already called
    /// <c>services.Configure&lt;SessionAuthenticationConfiguration&gt;(...)</c> elsewhere).
    /// </summary>
    /// <remarks>
    /// Single source of truth: every consumer - including the cookie/OIDC handlers and the
    /// token <see cref="HttpClient"/> - resolves <c>IOptions&lt;SessionAuthenticationConfiguration&gt;</c>.
    /// No registration-time snapshot is captured, so external
    /// <c>Configure&lt;T&gt;</c>/<c>PostConfigure&lt;T&gt;</c> composition is honored everywhere.
    /// </remarks>
    public static IServiceCollection AddPortaAuthentication(
        this IServiceCollection services,
        Action<SessionAuthenticationConfiguration>? configureOptions = null)
    {
        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }

        return services.AddPortaAuthenticationCore();
    }

    /// <summary>
    /// Shared registration body for both <see cref="AddPortaAuthentication(IServiceCollection, IConfiguration, string)"/>
    /// and <see cref="AddPortaAuthentication(IServiceCollection, Action{SessionAuthenticationConfiguration}?)"/>.
    /// All startup-time wiring (cookie names, OIDC scheme options, resilience timeouts) binds
    /// lazily from the composed <c>IOptions&lt;SessionAuthenticationConfiguration&gt;</c> pipeline
    /// rather than an eager snapshot, so it reflects every <c>Configure</c>/<c>PostConfigure</c>
    /// the consumer registered, in any order.
    /// </summary>
    private static IServiceCollection AddPortaAuthenticationCore(
        this IServiceCollection services)
    {
        // Validate options up-front so a misconfigured BFF fails at boot rather than
        // on the first OIDC redirect. ValidateOnStart promotes validation from
        // "on first resolve" to "on host start" so the failure surfaces as a
        // startup error instead of a 500 on the first request that touches the
        // options. The OidcAuthOptions subclass has its own validator registered
        // by AddPortaOidcAuth so we don't fire validation against an unconfigured
        // OidcAuthOptions when only AddPortaAuthentication is used.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<SessionAuthenticationConfiguration>,
                SessionAuthenticationConfigurationValidator>());
        services.AddOptions<SessionAuthenticationConfiguration>().ValidateOnStart();

        AddInfrastructure(services);
        AddCookieAndOidcAuthentication(services);
        services.AddAuthenticationCore();
        services.AddTokenServices();
        services.AddSessionManagement();
        services.AddOidcEndpoints();

        return services;
    }

    /// <summary>
    /// Registers infrastructure shared across the BFF auth pipeline:
    /// distributed-memory-cache fallback, ASP.NET Core session, data protection,
    /// and the custom <see cref="ITicketStore"/>.
    /// </summary>
    private static void AddInfrastructure(IServiceCollection services)
    {
        // Detect HA-fatal misconfigurations *before* installing fallbacks so we can
        // warn at startup. Both signals are evaluated again inside the hosted
        // startup check (HaConfigurationStartupCheck) which has access to ILogger.
        var distributedCachePreRegistered = services.Any(d => d.ServiceType == typeof(IDistributedCache));
        var refreshLockPreRegistered = services.Any(d => d.ServiceType == typeof(IRefreshLock));
        var inProcessRefreshLockAcknowledged = RefreshLockExtensions.IsInProcessRefreshLockAcknowledged(services);
        // Inspect the consumer-provided IRefreshLock (if any) and flag known
        // in-process implementations. Anything else is treated as distributed
        // (the consumer brought it; trust their intent).
        var consumerProvidedInProcessLock = refreshLockPreRegistered &&
            services.Any(d => d.ServiceType == typeof(IRefreshLock) &&
                              d.ImplementationType == typeof(RefreshLockRegistry));
        var dataProtectionPreConfigured = DataProtectionExtensions.IsConfigured(services);
        // Encryption-at-rest of persisted DP keys is enforced via the helper APIs,
        // which require a protectKeys action. Operators who deliberately want
        // unencrypted keys (dev, single-box with full-disk encryption) must call
        // services.AcknowledgeUnencryptedDataProtectionKeys to opt in. We forward
        // both signals separately so the startup check can additionally verify the
        // attestation is not hollow (a protectKeys action that registered no
        // IXmlEncryptor) by resolving the effective KeyManagementOptions at boot.
        var dataProtectionKeysEncryptionAttested = DataProtectionExtensions.IsKeysEncryptionAttested(services);
        var dataProtectionKeysEncryptionAcknowledged = DataProtectionExtensions.IsUnencryptedAcknowledged(services);

        // Provide an in-memory distributed cache fallback when no real one is registered.
        // AddDistributedMemoryCache uses TryAddSingleton internally, so a previous
        // registration (e.g. AddStackExchangeRedisCache) wins.
        services.AddDistributedMemoryCache();

        // Session, Data Protection and ticket-store options all bind from the composed
        // IOptions<SessionAuthenticationConfiguration> pipeline (deferred to options-build
        // time) rather than an eager registration-time snapshot, so external
        // Configure/PostConfigure of the configuration is honored.
        services.AddSession();
        services.AddOptions<Microsoft.AspNetCore.Builder.SessionOptions>()
            .Configure<IOptions<SessionAuthenticationConfiguration>>((options, cfg) =>
            {
                var config = cfg.Value;
                options.Cookie.Name = config.CookieName + ".session";
                options.Cookie.HttpOnly = config.Cookie.HttpOnly;
                options.Cookie.SecurePolicy = ParseSecurePolicy(config.Cookie.SecurePolicy);
                options.Cookie.SameSite = ParseSameSite(config.Cookie.SameSite);
                options.IdleTimeout = TimeSpan.FromMinutes(config.SessionTimeoutInMin);
                options.Cookie.IsEssential = true;
            });

        // Data Protection is required by DistributedCacheTicketStore + revocation, so
        // register unconditionally. Persistence backends (Redis) should be layered on
        // top via Aspire or the consuming app. SetApplicationName/SetDefaultKeyLifetime
        // are the eager-snapshot equivalents of configuring ApplicationDiscriminator /
        // KeyManagementOptions.NewKeyLifetime; we configure those from IOptions instead.
        services.AddDataProtection();
        services.AddOptions<DataProtectionOptions>()
            .Configure<IOptions<SessionAuthenticationConfiguration>>((options, cfg) =>
                options.ApplicationDiscriminator =
                    ResolveDataProtectionApplicationName(cfg.Value.DataProtection.ApplicationName));
        services.AddOptions<KeyManagementOptions>()
            .Configure<IOptions<SessionAuthenticationConfiguration>>((options, cfg) =>
                options.NewKeyLifetime = TimeSpan.FromDays(cfg.Value.DataProtection.KeyLifetimeDays));

        // Always register the ticket store + its options. Cookies carry only an
        // opaque id; tokens live server-side.
        services.AddOptions<TicketStoreOptions>()
            .Configure<IOptions<SessionAuthenticationConfiguration>>((opts, cfg) =>
                opts.DefaultSlidingExpiration = TimeSpan.FromMinutes(cfg.Value.SessionTimeoutInMin));
        services.AddSingleton<ITicketStore, DistributedCacheTicketStore>();

        // Refresh-lock auto-pick. A consumer-provided IRefreshLock always wins.
        // Otherwise: distributed cache present → IDistributedCache-backed lock
        // (HA-safe by default); no distributed cache → in-process registry
        // (correct for single-instance dev/test). The startup check enforces
        // that an HA deployment without a proper distributed lock is either
        // explicitly acknowledged or refused.
        if (!refreshLockPreRegistered)
        {
            if (distributedCachePreRegistered)
            {
                services.AddSingleton<IRefreshLock, DistributedCacheRefreshLock>();
            }
            else
            {
                services.AddSingleton<IRefreshLock, RefreshLockRegistry>();
            }
        }

        // HA-readiness check: emit a single startup warning if the consumer hasn't
        // registered shared distributed cache or shared Data Protection persistence.
        // Both are HA-fatal: without them, running >1 replica behind a load balancer
        // will produce sign-in failures and cookies that don't decrypt cross-instance.
        services.AddHostedService(sp => new HaConfigurationStartupCheck(
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<HaConfigurationStartupCheck>>(),
            sp.GetRequiredService<Microsoft.Extensions.Hosting.IHostEnvironment>(),
            sp,
            distributedCacheConfigured: distributedCachePreRegistered,
            dataProtectionPersistenceConfigured: dataProtectionPreConfigured,
            dataProtectionKeysEncryptionAttested: dataProtectionKeysEncryptionAttested,
            dataProtectionKeysEncryptionAcknowledged: dataProtectionKeysEncryptionAcknowledged,
            distributedRefreshLockConfiguredOrAcknowledged:
                IsDistributedRefreshLockConfiguredOrAcknowledged(
                    distributedCachePreRegistered,
                    consumerProvidedInProcessLock,
                    inProcessRefreshLockAcknowledged)));

        // Transport-security downgrade guard: refuse to start (outside Development) when the
        // operator has loosened a secure default - SecurePolicy != Always or
        // RequireHttpsMetadata == false - either of which exposes the cookie / OIDC metadata
        // over plaintext HTTP. Reads IOptions<SessionAuthenticationConfiguration> (the effective
        // bound options) rather than the snapshot, since the OIDC path binds via Configure<>.
        services.AddHostedService<CookieSecurityStartupCheck>();
    }

    /// <summary>
    /// True unless the deployment looks HA (distributed cache present) and the
    /// consumer explicitly pre-registered the in-process <see cref="RefreshLockRegistry"/>
    /// without calling <see cref="RefreshLockExtensions.AcknowledgeInProcessRefreshLock"/>.
    /// The startup check uses this to refuse boot in non-Development when the
    /// in-process lock would be silently used on a multi-replica deployment.
    /// </summary>
    private static bool IsDistributedRefreshLockConfiguredOrAcknowledged(
        bool distributedCachePreRegistered,
        bool consumerProvidedInProcessLock,
        bool inProcessRefreshLockAcknowledged)
    {
        if (!distributedCachePreRegistered)
        {
            return true;
        }
        if (!consumerProvidedInProcessLock)
        {
            return true;
        }
        return inProcessRefreshLockAcknowledged;
    }

    /// <summary>
    /// Registers ASP.NET Core's cookie + OpenIdConnect handlers and wires the
    /// <c>OnTokenValidated</c> event to <see cref="ISessionManagementService.RegisterSessionAsync"/>.
    /// </summary>
    private static void AddCookieAndOidcAuthentication(IServiceCollection services)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie()
        .AddOpenIdConnect();

        // Bind the cookie handler options from the composed configuration pipeline plus the
        // resolved ITicketStore. Deferring to options-build time (instead of an eager snapshot)
        // means external Configure/PostConfigure of SessionAuthenticationConfiguration is honored.
        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<IOptions<SessionAuthenticationConfiguration>, ITicketStore>((opts, cfg, store) =>
            {
                var config = cfg.Value;
                opts.Cookie.Name = config.CookieName;
                opts.Cookie.HttpOnly = config.Cookie.HttpOnly;
                opts.Cookie.SecurePolicy = ParseSecurePolicy(config.Cookie.SecurePolicy);
                opts.Cookie.SameSite = ParseSameSite(config.Cookie.SameSite);
                opts.Cookie.IsEssential = true;
                opts.ExpireTimeSpan = TimeSpan.FromMinutes(config.Cookie.ExpireTimeSpanMinutes);
                opts.SlidingExpiration = config.Cookie.SlidingExpiration;

                // Server-side ticket storage: cookie carries only the opaque id.
                opts.SessionStore = store;
            });

        // Likewise bind the OpenIdConnect handler from the composed configuration. A prior
        // implementation snapshotted these values at registration, so callers using normal
        // Configure/PostConfigure composition could end up with an empty/default handler
        // (ClientId="", no Authority) while IOptions validated correctly.
        services.AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
            .Configure<IOptions<SessionAuthenticationConfiguration>>((options, cfg) =>
            {
                var config = cfg.Value;
                options.Authority = config.Authority;
                options.ClientId = config.ClientId;
                options.ClientSecret = config.ClientSecret;
                options.RequireHttpsMetadata = config.RequireHttpsMetadata;
                options.ResponseType = "code";
                options.UsePkce = config.UsePkce;
                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = config.QueryUserInfoEndpoint;

                options.Scope.Clear();
                foreach (var s in (config.Scope ?? "openid profile email").Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    options.Scope.Add(s);
                }

                // The signing scheme is the cookie scheme - this is what triggers
                // ITicketStore on successful sign-in.
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                options.Events.OnTokenValidated = OnTokenValidatedAsync;
            });
    }

    /// <summary>
    /// Called by the OIDC handler after id_token validation. We pull the refresh
    /// token off the token-endpoint response, encrypt it, and register the session
    /// with <see cref="ISessionManagementService"/> so that admin force-logout and
    /// back-channel logout flows can reach this session and revoke its tokens at
    /// the IdP.
    /// </summary>
    private static async Task OnTokenValidatedAsync(TokenValidatedContext context)
    {
        var sp = context.HttpContext.RequestServices;
        var sessionManagement = sp.GetService<ISessionManagementService>();
        if (sessionManagement is null)
        {
            return;
        }

        var principal = context.Principal;
        if (principal is null)
        {
            return;
        }

        // `sub` is the primary identity key. It's the only OIDC claim guaranteed to be a
        // unique, stable, IdP-scoped identifier for the end user (OIDC Core §2). Without
        // it we have nothing safe to index sessions by - bail.
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return;
        }

        // Email is a *secondary* index, used only for admin lookups by address. We accept
        // it strictly when the IdP attests `email_verified=true`. We never fall back to
        // `preferred_username`: per OIDC Core §5.7 it is neither unique nor verified, so
        // using it as an email-index key would collide distinct users and let an
        // unverified account squat on another user's address.
        var email = principal.FindFirst(ClaimTypes.Email)?.Value
            ?? principal.FindFirst("email")?.Value;
        var emailVerified = principal.FindFirst("email_verified")?.Value;
        if (!string.Equals(emailVerified, "true", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(emailVerified, bool.TrueString, StringComparison.OrdinalIgnoreCase))
        {
            email = null;
        }

        var refreshToken = context.TokenEndpointResponse?.RefreshToken;
        var encryptedRefreshToken = sessionManagement.ProtectRefreshToken(refreshToken);

        var ip = context.HttpContext.Connection.RemoteIpAddress?.ToString();
        var userAgent = context.HttpContext.Request.Headers.UserAgent.ToString();

        // The cookie ticket id won't exist until SignInAsync runs (after this event).
        // Prefer the IdP-issued `sid` (per-login, addressable by back-channel logout),
        // otherwise mint a fresh per-login id. We deliberately do NOT fall back to
        // `sub`: it's stable across logins, so reusing it would collapse multiple
        // concurrent logins for one user onto a single metadata record.
        var sessionId = principal.FindFirst("sid")?.Value
            ?? Guid.NewGuid().ToString("N");

        // Stash the sessionId on the auth properties so that:
        //  1) DistributedCacheTicketStore.StoreAsync can use it as the ticket key
        //     (keeping metadata and ticket addressable by the same id), and
        //  2) AccessTokenRefreshService can sync rotated refresh tokens onto the
        //     same session metadata record.
        if (context.Properties is not null)
        {
            context.Properties.Items[SessionIdPropertyKey] = sessionId;
        }

        await sessionManagement.RegisterSessionAsync(
            sessionId,
            userId: userId,
            email: email,
            ipAddress: ip,
            userAgent: userAgent,
            encryptedRefreshToken: encryptedRefreshToken);
    }

    /// <summary>
    /// AuthenticationProperties.Items key under which the BFF-assigned sessionId is
    /// stored. Shared by the ticket store and the refresh path so all three
    /// (metadata, ticket, rotated tokens) stay addressable by the same id.
    /// </summary>
    internal const string SessionIdPropertyKey = ".bff.session_id";

    // Fail-fast parsers: a typo in appsettings (e.g. "Allways") used to silently
    // downgrade the cookie's secure policy or pin SameSite back to a default,
    // masking the misconfiguration. Throwing at startup forces the operator to
    // fix the value instead of shipping with weaker cookie security than intended.
    /// <summary>
    /// Resolves the Data Protection application name. An explicit non-empty
    /// config value wins; otherwise we derive a stable per-host name from the
    /// entry assembly so two unrelated BFFs on shared infrastructure don't
    /// collide on the purpose-string namespace. Falls back to <c>"Porta"</c> if
    /// the entry assembly can't be resolved (e.g. unit tests).
    /// </summary>
    internal static string ResolveDataProtectionApplicationName(string configured)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        var entry = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name;
        return string.IsNullOrWhiteSpace(entry) ? "Porta" : $"{entry}/Porta";
    }

    private static CookieSecurePolicy ParseSecurePolicy(string value) => value switch
    {
        "Always" => CookieSecurePolicy.Always,
        "SameAsRequest" => CookieSecurePolicy.SameAsRequest,
        "None" => CookieSecurePolicy.None,
        _ => throw new InvalidOperationException(
            $"Invalid Cookie.SecurePolicy value '{value}'. Expected one of: " +
            "Always, SameAsRequest, None."),
    };

    private static SameSiteMode ParseSameSite(string value) => value switch
    {
        "Strict" => SameSiteMode.Strict,
        "Lax" => SameSiteMode.Lax,
        "None" => SameSiteMode.None,
        _ => throw new InvalidOperationException(
            $"Invalid Cookie.SameSite value '{value}'. Expected one of: " +
            "Strict, Lax, None."),
    };

    /// <summary>
    /// Adds core authentication providers and context services.
    /// </summary>
    private static IServiceCollection AddAuthenticationCore(
        this IServiceCollection services)
    {
        // Token storage (session-based with optional encryption)
        services.AddScoped<ITokenStorage, SessionTokenStorage>();

        // Register IReferenceTokenService for ReferenceTokenAuthProvider.
        // TryAdd so AddReferenceTokenAuthentication (opt-in) doesn't double-register.
        services.TryAddSingleton<IReferenceTokenService, ReferenceTokenService>();

        // Authentication providers
        services.AddScoped<SessionAuthProvider>();
        services.AddScoped<ReferenceTokenAuthProvider>();

        // Register SessionAuthProvider as a composable provider. Multiple providers
        // can be registered side-by-side (session + JWT + reference token + custom);
        // see CompositeAuthenticationProvider for resolution semantics.
        services.AddScoped<IAuthenticationProviderRegistration>(sp =>
            new AuthenticationProviderRegistration(sp.GetRequiredService<SessionAuthProvider>()));

        // Discovery service for OIDC configuration
        services.AddSingleton<IDiscoveryService, DiscoveryService>();

        return services;
    }

    /// <summary>
    /// Adds token services (refresh, exchange, revocation, introspection).
    /// </summary>
    private static IServiceCollection AddTokenServices(
        this IServiceCollection services)
    {
        // Add named HttpClient for token operations with resilience. Both the client
        // timeout and the resilience policy bind from the composed
        // IOptions<SessionAuthenticationConfiguration> pipeline (read at resolve /
        // options-build time) rather than an eager registration-time snapshot, so
        // external Configure/PostConfigure of the configuration is honored.
        services.AddHttpClient(TokenHttpClientName, (sp, client) =>
        {
            var config = sp.GetRequiredService<IOptions<SessionAuthenticationConfiguration>>().Value;
            client.Timeout = TimeSpan.FromSeconds(config.Resilience.RequestTimeoutSeconds);
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddStandardResilienceHandler()
        .Configure((options, sp) =>
        {
            // Configure resilience based on configuration
            var config = sp.GetRequiredService<IOptions<SessionAuthenticationConfiguration>>().Value;
            options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(config.Resilience.RequestTimeoutSeconds);
            options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(config.Resilience.RequestTimeoutSeconds * 2);

            if (config.Resilience.EnableRetry)
            {
                options.Retry.MaxRetryAttempts = config.Resilience.MaxRetryAttempts;
                options.Retry.Delay = TimeSpan.FromSeconds(config.Resilience.InitialDelaySeconds);
                options.Retry.UseJitter = config.Resilience.UseJitter;
            }

            if (config.Resilience.EnableCircuitBreaker)
            {
                options.CircuitBreaker.FailureRatio = config.Resilience.CircuitBreakerFailureRatio;
                options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(config.Resilience.CircuitBreakerSamplingDurationSeconds);
                options.CircuitBreaker.MinimumThroughput = config.Resilience.CircuitBreakerMinimumThroughput;
                options.CircuitBreaker.BreakDuration = TimeSpan.FromSeconds(config.Resilience.CircuitBreakerBreakDurationSeconds);
            }
        });

        // PortaCoreOptions is also registered by AddPortaCore; ensure the options
        // pipeline is wired here so AddPortaAuthentication standalone (no AddPortaCore)
        // still resolves the IOptions<PortaCoreOptions> dependency on
        // AccessTokenRefreshService / ApiTokenService for TokenRefreshSkew.
        // AddOptions<T>() is idempotent - any earlier Configure<PortaCoreOptions>(...)
        // wins.
        services.AddOptions<PortaCoreOptions>();

        // Guard against the named-client registration getting out of sync with the
        // const string consumers resolve by. If the name is missing at startup,
        // IHttpClientFactory silently returns the default unconfigured client and
        // the standard resilience handler is bypassed for every auth call.
        services.AddHostedService<AuthHttpClientStartupCheck>();

        // Register token services
        services.AddScoped<ITokenRefreshService, TokenRefreshService>();
        services.AddScoped<ITokenExchangeService, TokenExchangeService>();
        services.AddScoped<ITokenRevocationService, TokenRevocationService>();
        services.AddScoped<IApiTokenService, ApiTokenService>();
        // Refresh-lock registration is performed in AddInfrastructure, where the
        // pre-fallback IDistributedCache signal is still observable. See there.
        services.AddScoped<IAccessTokenRefreshService>(sp => new AccessTokenRefreshService(
            sp.GetRequiredService<ITokenRefreshService>(),
            sp.GetRequiredService<IApiTokenService>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<AccessTokenRefreshService>>(),
            sp.GetRequiredService<IRefreshLock>(),
            sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<PortaCoreOptions>>(),
            sessionManagement: sp.GetService<ISessionManagementService>(),
            ticketStore: sp.GetService<Microsoft.AspNetCore.Authentication.Cookies.ITicketStore>()));

        return services;
    }

    /// <summary>
    /// Adds session management services for admin operations.
    /// </summary>
    private static IServiceCollection AddSessionManagement(
        this IServiceCollection services)
    {
        services.AddScoped<ISessionManagementService, SessionManagementService>();

        return services;
    }

    /// <summary>
    /// Adds reference token authentication services (for API-to-API scenarios).
    /// </summary>
    public static IServiceCollection AddReferenceTokenAuthentication(
        this IServiceCollection services,
        Action<ReferenceTokenAuthOptions> configureOptions)
    {
        services.Configure(configureOptions);

        services.AddHttpClient(ReferenceTokenService.HttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(30);
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddStandardResilienceHandler();

        services.TryAddSingleton<IReferenceTokenService, ReferenceTokenService>();
        services.TryAddScoped<ReferenceTokenAuthProvider>();
        services.AddScoped<IAuthenticationProviderRegistration>(sp =>
            new AuthenticationProviderRegistration(sp.GetRequiredService<ReferenceTokenAuthProvider>()));

        return services;
    }

    /// <summary>
    /// Adds JWT bearer authentication for inbound requests. Opt-in alternative to reference tokens
    /// for environments where introspection is not available.
    /// </summary>
    /// <remarks>
    /// Reference tokens remain the recommended default in a BFF context (see the README design note).
    /// Use this when your IdP issues JWTs and you cannot introspect - e.g., legacy partners, B2B
    /// federation, or third-party APIs that hand callers JWTs directly.
    /// <para/>
    /// Signing keys are fetched from the OIDC discovery document at <see cref="JwtBearerAuthOptions.Authority"/>
    /// and rotated automatically. The provider does not refresh tokens; clients must obtain new ones
    /// before expiry.
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Services.AddPortaJwtAuthentication(options =>
    /// {
    ///     options.Authority = "https://auth.example.com";
    ///     options.ValidAudiences = ["my-porta"];
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaJwtAuthentication(
        this IServiceCollection services,
        Action<JwtBearerAuthOptions> configureOptions)
    {
        services.Configure(configureOptions);

        var options = new JwtBearerAuthOptions();
        configureOptions(options);

        services.AddAuthentication()
            .AddJwtBearer(jwtOptions =>
            {
                jwtOptions.Authority = options.Authority;
                jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;
                jwtOptions.SaveToken = true; // Required so JwtBearerAuthProvider can extract the raw token

                jwtOptions.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = options.ValidateIssuer,
                    ValidIssuers = options.ValidIssuers.Count > 0 ? options.ValidIssuers : null,
                    ValidateAudience = options.ValidateAudience,
                    ValidAudiences = options.ValidAudiences,
                    ValidateLifetime = options.ValidateLifetime,
                    ClockSkew = options.ClockSkew,
                    ValidAlgorithms = JwtValidationHelper.AllowedAsymmetricAlgorithms
                };
            });

        services.TryAddScoped<JwtBearerAuthProvider>();
        services.AddScoped<IAuthenticationProviderRegistration>(sp =>
            new AuthenticationProviderRegistration(sp.GetRequiredService<JwtBearerAuthProvider>()));

        return services;
    }

    /// <summary>
    /// Registers a custom authentication provider.
    /// </summary>
    /// <typeparam name="TProvider">The custom authentication provider type implementing <see cref="IAuthenticationProvider"/></typeparam>
    /// <param name="services">The service collection</param>
    /// <returns>The service collection for chaining</returns>
    /// <remarks>
    /// Use this method to register custom authentication providers for scenarios not covered by
    /// the built-in providers (session-based OIDC or reference token).
    ///
    /// Common use cases:
    /// <list type="bullet">
    ///   <item>API key authentication</item>
    ///   <item>HMAC signature validation</item>
    ///   <item>Custom JWT validation</item>
    ///   <item>External identity provider integration</item>
    /// </list>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Register custom provider
    /// builder.Services.AddPortaAuthProvider&lt;ApiKeyAuthProvider&gt;();
    ///
    /// // Or with factory
    /// builder.Services.AddPortaAuthProvider&lt;ApiKeyAuthProvider&gt;(sp =>
    ///     new ApiKeyAuthProvider(sp.GetRequiredService&lt;IApiKeyValidator&gt;()));
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaAuthProvider<TProvider>(this IServiceCollection services)
        where TProvider : class, IAuthenticationProvider
    {
        services.AddScoped<TProvider>();
        services.AddScoped<IAuthenticationProviderRegistration>(sp =>
            new AuthenticationProviderRegistration(sp.GetRequiredService<TProvider>()));

        return services;
    }

    /// <summary>
    /// Registers a custom authentication provider using a factory function.
    /// </summary>
    /// <typeparam name="TProvider">The custom authentication provider type implementing <see cref="IAuthenticationProvider"/></typeparam>
    /// <param name="services">The service collection</param>
    /// <param name="implementationFactory">Factory function to create the provider instance</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddPortaAuthProvider<TProvider>(
        this IServiceCollection services,
        Func<IServiceProvider, TProvider> implementationFactory)
        where TProvider : class, IAuthenticationProvider
    {
        services.AddScoped<TProvider>(implementationFactory);
        services.AddScoped<IAuthenticationProviderRegistration>(sp =>
            new AuthenticationProviderRegistration(sp.GetRequiredService<TProvider>()));

        return services;
    }
}
