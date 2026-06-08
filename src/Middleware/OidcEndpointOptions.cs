namespace b17s.Porta.Middleware;

/// <summary>
/// Configuration options for the OIDC login endpoint.
/// </summary>
public sealed class OidcLoginOptions
{
    /// <summary>
    /// Default URI to redirect to after login if no redirect_uri is provided.
    /// Default: "/"
    /// </summary>
    public string DefaultRedirectUri { get; set; } = "/";

    /// <summary>
    /// Whitelist of allowed redirect hosts for security.
    /// Entries may be a bare hostname (any port matches) or <c>host:port</c> to
    /// pin a specific port. Hostnames are compared in IDN/punycode form, so
    /// listing the punycode value matches the unicode form and vice versa.
    /// If empty, only same-origin and (when <see cref="AllowLocalhost"/> is true)
    /// localhost redirects are allowed.
    /// Example: ["app.example.com", "staging.example.com:8443"]
    /// </summary>
    public List<string> AllowedRedirectHosts { get; set; } = [];

    /// <summary>
    /// When true, loopback hosts (localhost, 127.0.0.0/8, ::1) are accepted as
    /// redirect targets even when <see cref="AllowedRedirectHosts"/> does not
    /// list them. In docker/sidecar deployments this is exploitable, so the
    /// default is <c>false</c>; turn this on only for local dev.
    /// </summary>
    public bool AllowLocalhost { get; set; } = false;

    // Note: scopes and PKCE are configured at the OIDC handler level via
    // SessionAuthenticationConfiguration (handler-owned). Endpoint-level
    // AdditionalScopes / UsePkce were never wired through to AuthenticationProperties
    // and were removed before 1.0 to avoid the appearance of being configurable here.

    /// <summary>
    /// When true, an unauthenticated caller may only specify the post-login
    /// destination via a signed <c>return_url</c> token issued by this server.
    /// A raw <c>redirect_uri</c> from an unauthenticated caller is ignored and
    /// <see cref="DefaultRedirectUri"/> is used instead. This blocks attacker-
    /// crafted login links from pre-setting internal target paths.
    /// Default: true.
    /// </summary>
    public bool RequireSignedReturnUrl { get; set; } = true;

    /// <summary>
    /// Lifetime of signed return-URL tokens minted via the helper endpoint.
    /// Default: 10 minutes.
    /// </summary>
    public TimeSpan ReturnUrlTtl { get; set; } = TimeSpan.FromMinutes(10);
}

/// <summary>
/// Configuration options for the OIDC logout endpoint.
/// </summary>
public sealed class OidcLogoutOptions
{
    /// <summary>
    /// Whitelist of allowed redirect hosts for security.
    /// Entries may be a bare hostname (any port matches) or <c>host:port</c> to
    /// pin a specific port. Hostnames are compared in IDN/punycode form.
    /// If empty, only same-origin and (when <see cref="AllowLocalhost"/> is true)
    /// localhost redirects are allowed.
    /// Example: ["app.example.com", "staging.example.com:8443"]
    /// </summary>
    public List<string> AllowedRedirectHosts { get; set; } = [];

    /// <summary>
    /// When true, loopback hosts (localhost, 127.0.0.0/8, ::1) are accepted as
    /// redirect targets even when <see cref="AllowedRedirectHosts"/> does not
    /// list them. In docker/sidecar deployments this is exploitable, so the
    /// default is <c>false</c>; turn this on only for local dev.
    /// </summary>
    public bool AllowLocalhost { get; set; } = false;

    /// <summary>
    /// Default URI to redirect to after logout if no redirect_uri is provided.
    /// Default: "/"
    /// </summary>
    public string DefaultRedirectUri { get; set; } = "/";

    /// <summary>
    /// Whether to return JSON response instead of redirecting.
    /// When true, returns { success: true, redirectUrl: "..." }.
    /// Default: false (redirect)
    /// </summary>
    public bool ReturnJson { get; set; } = false;

    /// <summary>
    /// Whether to perform global logout or local-session-only logout.
    /// Default: true (global logout).
    /// </summary>
    /// <remarks>
    /// The exact effect depends on <see cref="ReturnJson"/>:
    /// <list type="bullet">
    ///   <item><b>Redirect mode</b> (<see cref="ReturnJson"/> = <c>false</c>):
    ///     revokes the refresh token at the IdP (RFC 7009) <i>and</i> signs out the
    ///     OIDC scheme, so the framework redirects the browser to the IdP
    ///     end-session endpoint - this terminates the IdP SSO session too.</item>
    ///   <item><b>JSON mode</b> (<see cref="ReturnJson"/> = <c>true</c>): revokes
    ///     the refresh token at the IdP (RFC 7009) and clears the local BFF
    ///     session, but does <b>not</b> end the IdP SSO session. A JSON response
    ///     cannot also issue the <c>302</c> the end-session redirect requires, so
    ///     the browser is never sent to the IdP. The SPA must terminate the IdP
    ///     session itself - see the "Global logout from a SPA" guidance in
    ///     <c>docs/oidc.md</c>.</item>
    /// </list>
    /// </remarks>
    public bool PerformGlobalLogout { get; set; } = true;

    /// <summary>
    /// When <c>true</c> (default), the <c>POST /bff/logout</c> endpoint requires
    /// a valid ASP.NET antiforgery token. The HTTP-method gate already blocks
    /// CSRF logout via <c>&lt;img src&gt;</c>/top-level GET, but this is
    /// defense-in-depth against cookie-policy drift (e.g. switching the auth
    /// cookie to <c>SameSite=None</c> for a cross-site embedded scenario, which
    /// would allow a cross-origin POST to attach the cookie and trigger logout
    /// + IdP-side revocation as a side effect).
    /// </summary>
    /// <remarks>
    /// The middleware uses <see cref="Microsoft.AspNetCore.Antiforgery.IAntiforgery"/>,
    /// which reads the token from the configured header (default
    /// <c>RequestVerificationToken</c>) or form field. A browser SPA should
    /// fetch a token via <c>IAntiforgery.GetAndStoreTokens</c> and attach it to
    /// the logout POST. Disable only if your logout callers are non-browser
    /// (CLI, native app with token auth).
    /// </remarks>
    public bool RequireAntiforgery { get; set; } = true;
}

/// <summary>
/// Configuration options for the OIDC back-channel logout endpoint.
/// </summary>
public sealed class OidcBackChannelLogoutOptions
{
    /// <summary>
    /// Maximum allowed clock skew for JWT validation.
    /// Default: 5 minutes
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether to validate the logout token signature.
    /// Should always be true in production - <see cref="Extensions.OidcEndpointExtensions.UseOidcBackChannelLogout"/>
    /// fails fast at startup when this is disabled outside Development.
    /// Default: true
    /// </summary>
    public bool ValidateSignature { get; set; } = true;

    /// <summary>
    /// Whether to validate the issuer claim.
    /// <see cref="Extensions.OidcEndpointExtensions.UseOidcBackChannelLogout"/>
    /// fails fast at startup when this is disabled outside Development.
    /// Default: true
    /// </summary>
    public bool ValidateIssuer { get; set; } = true;

    /// <summary>
    /// Whether to validate the audience claim.
    /// <see cref="Extensions.OidcEndpointExtensions.UseOidcBackChannelLogout"/>
    /// fails fast at startup when this is disabled outside Development.
    /// Default: true
    /// </summary>
    public bool ValidateAudience { get; set; } = true;

    /// <summary>
    /// Maximum allowed Content-Length for back-channel logout request bodies.
    /// The endpoint is anonymous, so this caps memory that an unauthenticated
    /// caller can force the server to buffer. A spec-compliant logout_token
    /// carries a single JWT of a few KB.
    /// Default: 64 KB.
    /// </summary>
    public long MaxRequestBodyBytes { get; set; } = 64 * 1024;

    /// <summary>
    /// Maximum allowed length of the logout_token string itself, in characters.
    /// Bounds JWT validator work for obviously-oversized tokens.
    /// Default: 16 KB.
    /// </summary>
    public int MaxLogoutTokenLength { get; set; } = 16 * 1024;

    /// <summary>
    /// When true (default), require the logout_token JWT header to carry
    /// <c>typ: logout+jwt</c> per OIDC Back-Channel Logout 1.0 §2.4. This is
    /// the primary defense against an attacker presenting a signed id_token or
    /// access_token from the same issuer/audience.
    ///
    /// Set to false only when integrating with a legacy IdP that mints logout
    /// tokens with <c>typ: JWT</c> or no <c>typ</c> header. The <c>events</c>
    /// claim still acts as a secondary check, but operating in this mode is
    /// less safe and should be considered a temporary compatibility setting.
    /// </summary>
    public bool RequireLogoutTypHeader { get; set; } = true;

    /// <summary>
    /// Upper bound on how long a consumed <c>jti</c> is kept in the replay cache.
    /// The runtime caches each consumed <c>jti</c> for <c>(token.ValidTo - UtcNow) + ClockSkew</c>,
    /// but if a misconfigured IdP mints a token with no <c>exp</c> claim that value
    /// can be effectively unbounded, exhausting the cache. The TTL is clamped to
    /// this value as a defense-in-depth limit.
    /// Default: 24 hours.
    /// </summary>
    public TimeSpan MaxReplayCacheTtl { get; set; } = TimeSpan.FromHours(24);
}

/// <summary>
/// Configuration options for the session admin endpoint.
/// </summary>
public sealed class SessionAdminOptions
{
    /// <summary>
    /// The authorization policy required to access session admin endpoints.
    /// This is REQUIRED - the endpoint will fail at startup if not specified
    /// or if the policy doesn't exist.
    /// </summary>
    /// <remarks>
    /// Example: "AdminOnly", "SessionAdmin", "RequireAdminRole"
    /// The policy must be registered via services.AddAuthorization(options => ...).
    /// </remarks>
    public string? RequirePolicy { get; set; }

    /// <summary>
    /// When <c>true</c> (default), state-changing requests (DELETE) on the admin
    /// endpoints require a valid ASP.NET antiforgery token whenever the
    /// authenticated caller is identified via a cookie scheme. Token-auth
    /// callers (bearer / reference tokens / API keys) are exempt because their
    /// credentials are not auto-attached cross-origin and so are not CSRF-vulnerable.
    /// </summary>
    /// <remarks>
    /// The middleware uses <see cref="Microsoft.AspNetCore.Antiforgery.IAntiforgery"/>,
    /// which reads the token from the configured header (default <c>RequestVerificationToken</c>)
    /// or form field. Browser admin UIs should fetch a token via
    /// <c>IAntiforgery.GetAndStoreTokens</c> and attach it to the DELETE request.
    /// Disable only if your admin clients are non-browser (CLI, server-to-server).
    /// </remarks>
    public bool RequireAntiforgery { get; set; } = true;
}
