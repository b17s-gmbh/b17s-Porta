using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Services;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Integration;

/// <summary>
/// Fluent builder that wires the recurring integration-test boilerplate
/// (TestServer, in-memory config, OIDC handler backchannel routing, named
/// FakeBackend HttpClients, endpoint mapping) into one place. Tests configure
/// only the bits that vary; everything else has sensible defaults.
/// </summary>
public sealed class PortaTestHost
{
    private FakeIdp? _idp;
    private readonly Dictionary<string, string?> _config = new(StringComparer.Ordinal);
    private readonly List<Action<IServiceCollection>> _serviceConfigs = [];
    private readonly List<Action<IApplicationBuilder>> _middlewareConfigs = [];
    private readonly List<Action<IEndpointRouteBuilder>> _endpointConfigs = [];
    private readonly Dictionary<string, FakeBackend> _backendsByHttpClient = new(StringComparer.Ordinal);
    private FakeBackend? _defaultBackend;
    private Action<PortaCoreOptions>? _coreOptions;
    private bool _addPortaCore = true;
    private bool _addPortaAuthentication;
    private bool _useAuthentication;
    private bool _useOidcLoginEndpoints;
    private bool _useAuthorization;
    private bool _useSession;
    private Action<OidcLogoutOptions>? _oidcLogoutConfigure;
    private bool _useBackChannelLogout;
    private bool _useSessionAdmin;
    private string _sessionAdminPath = "/bff/admin/sessions";
    private string? _sessionAdminPolicy;
    private Action<SessionAdminOptions>? _sessionAdminConfigure;

    /// <summary>
    /// Wires the OIDC handler's backchannel + the token client to a FakeIdp,
    /// and sets the SessionAuthentication config block to point at that
    /// authority. Enables the OIDC login/logout endpoints automatically.
    /// </summary>
    public PortaTestHost WithFakeIdp(FakeIdp idp)
    {
        _idp = idp;
        _config["SessionAuthentication:Authority"] = idp.Authority;
        _config["SessionAuthentication:ClientId"] = idp.ClientId;
        _config["SessionAuthentication:ClientSecret"] = idp.ClientSecret;
        _config["SessionAuthentication:Scope"] = "openid profile email";
        _config["SessionAuthentication:CookieName"] = "__Porta";
        _config["SessionAuthentication:UsePkce"] = "true";
        _config["SessionAuthentication:QueryUserInfoEndpoint"] = "false";
        _config["SessionAuthentication:Cookie:SecurePolicy"] = "None";
        _config["SessionAuthentication:Cookie:SameSite"] = "Lax";
        _addPortaAuthentication = true;
        _useAuthentication = true;
        _useOidcLoginEndpoints = true;
        return this;
    }

    /// <summary>
    /// Wires inbound reference-token (opaque token) authentication against a <see cref="FakeIdp"/>.
    /// Unlike <see cref="WithFakeIdp"/> this does NOT enable the OIDC cookie scheme or login
    /// endpoints: reference tokens are validated statelessly via RFC 7662 introspection, so there
    /// is no browser session. The provider's introspection client and the discovery client are
    /// routed to the fake authority, and the audience/issuer binding is defaulted to values that the
    /// fake's <see cref="FakeIdp.IssueReferenceToken"/> satisfies (audience <c>"api"</c>, issuer =
    /// authority, client_id = the fake's client). Pass <paramref name="configure"/> to override.
    /// </summary>
    /// <remarks>
    /// Because reference-token requests carry no cookie, the ASP.NET principal is never populated, so
    /// endpoints must NOT use <c>RequireAuth()</c> - its principal check would 401 before
    /// introspection ever runs. Gate them instead with a transformer whose
    /// <c>RequiresAuthentication</c> is true (it returns 401 when the introspected <c>sub</c> is
    /// absent) combined with <c>AllowAnonymous()</c> at the routing layer.
    /// </remarks>
    public PortaTestHost WithReferenceToken(FakeIdp idp, Action<ReferenceTokenAuthOptions>? configure = null)
    {
        // Setting _idp routes the discovery client (TokenHttpClientName) to the fake authority in
        // StartAsync, leaving the composite with only the reference-token provider. It does NOT
        // enable the OIDC scheme (that needs _addPortaAuthentication), so the harmless OIDC
        // PostConfigure callback never executes.
        _idp = idp;
        _serviceConfigs.Add(services =>
        {
            services.AddReferenceTokenAuthentication(opts =>
            {
                opts.Authority = idp.Authority;
                opts.ClientId = idp.ClientId;
                opts.ClientSecret = idp.ClientSecret;
                opts.ValidIssuers = [idp.Authority];
                opts.ValidAudiences = ["api"];
                opts.ValidClientIds = [idp.ClientId];
                configure?.Invoke(opts);
            });

            // Route the introspection client to the fake authority's /introspect endpoint.
            services.AddHttpClient(ReferenceTokenService.HttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => idp.BackchannelHandler);

            // ReferenceTokenService -> IDiscoveryService is normally pulled in by
            // AddPortaAuthentication, which this path deliberately skips. Register it directly and
            // drop the HTTPS-metadata requirement so discovery works over the fake's http authority.
            services.Configure<SessionAuthenticationConfiguration>(c => c.RequireHttpsMetadata = false);
            services.TryAddSingleton<IDiscoveryService, DiscoveryService>();

            // The provider caches introspection results in IDistributedCache.
            services.AddDistributedMemoryCache();
        });
        return this;
    }

    /// <summary>
    /// Adds <see cref="AuthorizationServiceCollectionExtensions.AddAuthorization(IServiceCollection)"/>
    /// and inserts <c>UseAuthorization</c> in the pipeline. Suite 1 transformer
    /// tests need this when they call <c>RequireAuthorization</c>; the bare OIDC
    /// tests don't.
    /// </summary>
    public PortaTestHost WithAuthorization()
    {
        _useAuthorization = true;
        _serviceConfigs.Add(s => s.AddAuthorization());
        return this;
    }

    /// <summary>
    /// Adds ASP.NET Core session (backed by an in-memory distributed cache) and inserts
    /// <c>UseSession</c> in the pipeline. <see cref="b17s.Porta.Auth.Sessions.SessionTokenStorage"/>
    /// persists the API-token (token-exchange) cache in <c>HttpContext.Session</c>, so the
    /// caching suite needs this wired - and a client whose session cookie round-trips
    /// (see <c>LoginWithCookieJarAsync</c>).
    /// </summary>
    public PortaTestHost WithSession()
    {
        _useSession = true;
        _serviceConfigs.Add(s =>
        {
            s.AddDistributedMemoryCache();
            s.AddSession(options =>
            {
                options.Cookie.Name = "__Porta.Session";
                options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.None;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.IsEssential = true;
            });
        });
        return this;
    }

    /// <summary>
    /// Configures the OIDC logout endpoint (enabled automatically by <see cref="WithFakeIdp"/>).
    /// Tests use this to e.g. set <c>RequireAntiforgery=false</c> so a POST /bff/logout from a
    /// cookie-jar-less client isn't rejected before the logout behaviour under test runs.
    /// </summary>
    public PortaTestHost ConfigureOidcLogout(Action<OidcLogoutOptions> configure)
    {
        _oidcLogoutConfigure = configure;
        return this;
    }

    /// <summary>
    /// Inserts the IdP-initiated back-channel logout endpoint (<c>/bff/backchannel-logout</c>) into
    /// the pipeline so a signed <c>logout_token</c> can terminate sessions out-of-band.
    /// </summary>
    public PortaTestHost WithBackChannelLogout()
    {
        _useBackChannelLogout = true;
        return this;
    }

    /// <summary>
    /// Inserts the session admin endpoints (<c>/bff/admin/sessions</c>) and registers the required
    /// authorization policy <paramref name="policy"/>, which is satisfied by any caller carrying a
    /// <c>porta_admin=true</c> claim (set it on <see cref="FakeIdp.NextUserIdentity"/> before login to
    /// mint an admin). <c>UseSessionAdmin</c> verifies the policy exists at host start.
    /// </summary>
    public PortaTestHost WithSessionAdmin(string policy = "SessionAdmin", Action<SessionAdminOptions>? configure = null)
    {
        _useSessionAdmin = true;
        _sessionAdminPolicy = policy;
        _sessionAdminConfigure = configure;
        _serviceConfigs.Add(s => s.AddAuthorization(options =>
            options.AddPolicy(policy, p => p.RequireAssertion(ctx =>
                ctx.User.HasClaim(c => c.Type == "porta_admin" && c.Value == "true")))));
        return this;
    }

    /// <summary>
    /// Routes the BackendCaller HttpClient at <paramref name="backend"/> so all
    /// outbound traffic from production code under test reaches the in-process
    /// fake. Multiple backends can be wired by passing distinct HttpClient
    /// names, but production callers all use the same one — so the default
    /// just rewires that single client.
    /// </summary>
    public PortaTestHost WithBackend(FakeBackend backend)
    {
        _defaultBackend = backend;
        _backendsByHttpClient[BackendCaller.HttpClientName] = backend;
        _backendsByHttpClient[BackendCaller.HttpClientNameWithRetries] = backend;
        // The backend we forward to is, by definition, a trusted internal host. Register its
        // authority in PortaCore:TrustedHosts so user-token-forwarding policies (WithUserToken,
        // BearerToken, TokenExchange) clear the startup + runtime trusted-host gate - mirroring a
        // real deployment. Tests that assert the gate REJECTS an untrusted host simply don't call
        // WithBackend (the host fails to boot before any backend is reached).
        return ConfigureCore(opts =>
        {
            if (!opts.TrustedHosts.Contains(backend.BaseAddress))
            {
                opts.TrustedHosts.Add(backend.BaseAddress);
            }
        });
    }

    /// <summary>
    /// Adds extra in-memory configuration entries (merged with the defaults).
    /// </summary>
    public PortaTestHost WithConfiguration(IDictionary<string, string?> entries)
    {
        foreach (var (k, v) in entries)
        {
            _config[k] = v;
        }
        return this;
    }

    /// <summary>
    /// Configure <see cref="PortaCoreOptions"/> (e.g. TrustedHosts) before
    /// AddPortaCore runs. Multiple calls are additive in order.
    /// </summary>
    public PortaTestHost ConfigureCore(Action<PortaCoreOptions> configure)
    {
        var existing = _coreOptions;
        _coreOptions = existing is null ? configure : opts => { existing(opts); configure(opts); };
        return this;
    }

    /// <summary>
    /// Skip the AddPortaCore call. Use when a test wants to register Porta
    /// pieces by hand.
    /// </summary>
    public PortaTestHost SkipPortaCore()
    {
        _addPortaCore = false;
        return this;
    }

    /// <summary>
    /// Adds arbitrary service registrations (transformer types, custom auth
    /// handlers, mock services).
    /// </summary>
    public PortaTestHost ConfigureServices(Action<IServiceCollection> configure)
    {
        _serviceConfigs.Add(configure);
        return this;
    }

    /// <summary>
    /// Adds endpoint declarations. Runs inside <c>UseEndpoints(...)</c>.
    /// </summary>
    public PortaTestHost MapEndpoints(Action<IEndpointRouteBuilder> configure)
    {
        _endpointConfigs.Add(configure);
        return this;
    }

    /// <summary>
    /// Adds middleware between routing and endpoints. Use sparingly.
    /// </summary>
    public PortaTestHost UseMiddleware(Action<IApplicationBuilder> configure)
    {
        _middlewareConfigs.Add(configure);
        return this;
    }

    /// <summary>
    /// Boots the host. Throws via <c>StartAsync</c> if any startup-time check
    /// fails — that's the behaviour suite 1 relies on for the
    /// TrustedHosts-rejects test.
    /// </summary>
    public async Task<IHost> StartAsync()
    {
        var idp = _idp;
        var addPortaCore = _addPortaCore;
        var addPortaAuthentication = _addPortaAuthentication;
        var useAuthentication = _useAuthentication;
        var useOidcLoginEndpoints = _useOidcLoginEndpoints;
        var useAuthorization = _useAuthorization;
        var useSession = _useSession;
        var oidcLogoutConfigure = _oidcLogoutConfigure;
        var useBackChannelLogout = _useBackChannelLogout;
        var useSessionAdmin = _useSessionAdmin;
        var sessionAdminPath = _sessionAdminPath;
        var sessionAdminPolicy = _sessionAdminPolicy;
        var sessionAdminConfigure = _sessionAdminConfigure;
        var configEntries = new Dictionary<string, string?>(_config);
        var serviceConfigs = _serviceConfigs.ToArray();
        var middlewareConfigs = _middlewareConfigs.ToArray();
        var endpointConfigs = _endpointConfigs.ToArray();
        var backends = new Dictionary<string, FakeBackend>(_backendsByHttpClient);
        var coreOptions = _coreOptions;

        var hostBuilder = new HostBuilder()
            // TestServer runs over plaintext HTTP, so the suite uses the secure-downgrade
            // defaults a real deployment would reject (SecurePolicy=None, RequireHttpsMetadata
            // =false). Declaring the Development environment is the documented escape hatch:
            // CookieSecurityStartupCheck warns instead of throwing there.
            .UseEnvironment(Environments.Development)
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();

                    var configuration = new ConfigurationBuilder()
                        .AddInMemoryCollection(configEntries)
                        .Build();
                    services.AddSingleton<IConfiguration>(configuration);

                    if (addPortaCore)
                    {
                        if (coreOptions is not null)
                        {
                            services.AddPortaCore(coreOptions);
                        }
                        else
                        {
                            services.AddPortaCore();
                        }
                    }

                    if (addPortaAuthentication)
                    {
                        services.AddPortaAuthentication(configuration);
                    }

                    if (idp is not null)
                    {
                        // Route OIDC handler + token client to the fake IdP.
                        services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, opts =>
                        {
                            opts.BackchannelHttpHandler = idp.BackchannelHandler;
                            opts.Backchannel = new HttpClient(idp.BackchannelHandler, disposeHandler: false);
                            opts.RequireHttpsMetadata = false;
                            opts.ConfigurationManager = new Microsoft.IdentityModel.Protocols.ConfigurationManager<Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration>(
                                opts.MetadataAddress ?? $"{idp.Authority}/.well-known/openid-configuration",
                                new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfigurationRetriever(),
                                new Microsoft.IdentityModel.Protocols.HttpDocumentRetriever(opts.Backchannel) { RequireHttps = false });
                        });

                        services.AddHttpClient(AuthenticationServiceExtensions.TokenHttpClientName)
                            .ConfigurePrimaryHttpMessageHandler(() => idp.BackchannelHandler);
                    }

                    foreach (var (clientName, backend) in backends)
                    {
                        var handler = backend.BackchannelHandler;
                        services.AddHttpClient(clientName)
                            .ConfigurePrimaryHttpMessageHandler(() => handler);
                    }

                    // No-IdP hosts register no authentication provider. AddPortaCore's
                    // CompositeAuthenticationProvider yields an unauthenticated context when zero
                    // providers are registered, so anonymous endpoints work without any extra wiring.

                    foreach (var configure in serviceConfigs)
                    {
                        configure(services);
                    }
                });

                webHost.Configure(app =>
                {
                    app.UseRouting();
                    if (useSession)
                    {
                        app.UseSession();
                    }
                    if (useAuthentication)
                    {
                        app.UseAuthentication();
                    }
                    if (useOidcLoginEndpoints)
                    {
                        app.UseOidcLogin();
                        app.UseOidcLogout("/bff/logout", oidcLogoutConfigure);
                    }
                    if (useBackChannelLogout)
                    {
                        app.UseOidcBackChannelLogout();
                    }
                    if (useSessionAdmin)
                    {
                        app.UseSessionAdmin(sessionAdminPath, opts =>
                        {
                            opts.RequirePolicy = sessionAdminPolicy!;
                            sessionAdminConfigure?.Invoke(opts);
                        });
                    }
                    if (useAuthorization)
                    {
                        app.UseAuthorization();
                    }
                    foreach (var configure in middlewareConfigs)
                    {
                        configure(app);
                    }
                    app.UseEndpoints(endpoints =>
                    {
                        foreach (var configure in endpointConfigs)
                        {
                            configure(endpoints);
                        }
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    /// <summary>
    /// Convenience overload used by simple unauthenticated suites — boots the
    /// host with a default backend wired and a single endpoint configuration
    /// callback.
    /// </summary>
    public static Task<IHost> StartWithBackendAsync(
        FakeBackend backend,
        Action<IEndpointRouteBuilder> mapEndpoints,
        Action<PortaTestHost>? configure = null)
    {
        var host = new PortaTestHost()
            .WithBackend(backend)
            .MapEndpoints(mapEndpoints);
        configure?.Invoke(host);
        return host.StartAsync();
    }
}

