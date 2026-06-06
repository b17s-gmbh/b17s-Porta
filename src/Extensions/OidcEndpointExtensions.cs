using b17s.Porta.Middleware;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Extensions;

/// <summary>
/// Extension methods for configuring OIDC endpoints as opt-in middleware.
/// </summary>
public static class OidcEndpointExtensions
{
    /// <summary>
    /// Adds an OIDC login endpoint that initiates the authorization code flow.
    /// This endpoint redirects to the IdP for authentication.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="path">The login endpoint path (default: "/bff/login")</param>
    /// <param name="configureOptions">Optional action to configure login options</param>
    /// <returns>The application builder for chaining</returns>
    /// <remarks>
    /// <para>
    /// This middleware handles the login initiation flow:
    /// <list type="number">
    ///   <item>Validates the optional redirect_uri query parameter</item>
    ///   <item>Generates CSRF state and nonce parameters</item>
    ///   <item>Generates PKCE code_verifier and code_challenge (if enabled)</item>
    ///   <item>Redirects to the IdP's authorization endpoint</item>
    /// </list>
    /// </para>
    /// <para>
    /// After successful authentication, the IdP redirects back to /bff/callback
    /// which should be handled by your OIDC callback handler.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Basic usage
    /// app.UseOidcLogin();
    ///
    /// // With custom path and options
    /// app.UseOidcLogin("/auth/login", options => {
    ///     options.DefaultRedirectUri = "/dashboard";
    ///     options.AllowedRedirectHosts = ["app.example.com", "staging.example.com"];
    /// });
    /// </code>
    /// </example>
    public static IApplicationBuilder UseOidcLogin(
        this IApplicationBuilder app,
        string path = "/bff/login",
        Action<OidcLoginOptions>? configureOptions = null)
    {
        // Configure options
        var options = new OidcLoginOptions();
        configureOptions?.Invoke(options);

        var failure = RedirectUriValidation.ValidateConfiguredRedirectUri(
            options.DefaultRedirectUri,
            options.AllowedRedirectHosts,
            options.AllowLocalhost);
        if (failure is not null)
        {
            throw new OptionsValidationException(
                nameof(OidcLoginOptions),
                typeof(OidcLoginOptions),
                [$"{nameof(OidcLoginOptions.DefaultRedirectUri)}: {failure}"]);
        }

        // Use middleware with path and options
        // Constructor signature: (RequestDelegate next, IOptions<OidcLoginOptions> options, IReturnUrlProtector protector, ILogger<OidcLoginMiddleware> logger, string path)
        app.UseMiddleware<OidcLoginMiddleware>(
            Options.Create(options),
            path);

        return app;
    }

    /// <summary>
    /// Adds an OIDC logout endpoint with redirect validation.
    /// Supports both local (session only) and global (session + IdP) logout.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="path">The logout endpoint path (default: "/bff/logout")</param>
    /// <param name="configureOptions">Optional action to configure logout options</param>
    /// <returns>The application builder for chaining</returns>
    /// <remarks>
    /// <para>
    /// This middleware handles logout with security-focused redirect validation:
    /// <list type="bullet">
    ///   <item>Validates that the user is authenticated before logging out</item>
    ///   <item>Validates redirect_uri against whitelist to prevent open redirects</item>
    ///   <item>Optionally revokes tokens at the IdP (global logout)</item>
    ///   <item>Clears the local session</item>
    ///   <item>Redirects to the IdP's end_session_endpoint or the specified URI</item>
    /// </list>
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Basic usage - global logout with redirect
    /// app.UseOidcLogout();
    ///
    /// // JSON response mode for SPA
    /// app.UseOidcLogout("/auth/logout", options => {
    ///     options.ReturnJson = true;
    ///     options.PerformGlobalLogout = true;
    ///     options.AllowedRedirectHosts = ["app.example.com"];
    /// });
    ///
    /// // Local logout only (no IdP round-trip)
    /// app.UseOidcLogout("/auth/logout", options => {
    ///     options.PerformGlobalLogout = false;
    /// });
    /// </code>
    /// </example>
    public static IApplicationBuilder UseOidcLogout(
        this IApplicationBuilder app,
        string path = "/bff/logout",
        Action<OidcLogoutOptions>? configureOptions = null)
    {
        // Configure options
        var options = new OidcLogoutOptions();
        configureOptions?.Invoke(options);

        var failure = RedirectUriValidation.ValidateConfiguredRedirectUri(
            options.DefaultRedirectUri,
            options.AllowedRedirectHosts,
            options.AllowLocalhost);
        if (failure is not null)
        {
            throw new OptionsValidationException(
                nameof(OidcLogoutOptions),
                typeof(OidcLogoutOptions),
                [$"{nameof(OidcLogoutOptions.DefaultRedirectUri)}: {failure}"]);
        }

        // Global logout drives an OIDC SignOutAsync, which relies on the framework
        // handler to attach id_token_hint from the saved tokens on the auth ticket.
        // If SaveTokens=false the hint is missing and many IdPs reject the
        // end-session request or skip the post-logout redirect - record the
        // requirement here so OidcEndpointStartupCheck can verify it after the
        // host is built, using async APIs as intended.
        if (options.PerformGlobalLogout)
        {
            var registry = app.ApplicationServices.GetService<OidcEndpointPipelineRegistry>()
                ?? throw new InvalidOperationException(
                    "UseOidcLogout requires services.AddOidcEndpoints() to have been called " +
                    "(or AddPortaOidcAuth, which wires it internally).");
            registry.RequireGlobalLogoutPreconditions();
        }

        // Use middleware with path and options
        app.UseMiddleware<OidcLogoutMiddleware>(
            Options.Create(options),
            path);

        return app;
    }

    /// <summary>
    /// Adds an OIDC back-channel logout endpoint for IdP-initiated logout.
    /// This enables "logout from one app = logout from all apps" functionality.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="path">The back-channel logout endpoint path (default: "/bff/backchannel-logout")</param>
    /// <param name="configureOptions">Optional action to configure back-channel logout options</param>
    /// <returns>The application builder for chaining</returns>
    /// <remarks>
    /// <para>
    /// Back-channel logout is an IdP-initiated flow where the IdP sends a signed JWT
    /// (logout_token) directly to this endpoint when a user logs out from another app.
    /// </para>
    /// <para>
    /// This is the one exception to the library's "no JWT validation" policy, as the
    /// logout_token must be validated to prevent malicious logout requests.
    /// </para>
    /// <para>
    /// The endpoint validates:
    /// <list type="bullet">
    ///   <item>JWT signature against the IdP's JWKS</item>
    ///   <item>Issuer (iss), audience (aud), expiration (exp) claims</item>
    ///   <item>The 'events' claim contains the back-channel logout event type</item>
    ///   <item>Extracts 'sid' (session ID) to identify which session to invalidate</item>
    /// </list>
    /// </para>
    /// <para>
    /// Important: Register this endpoint with your IdP's back-channel logout configuration.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Basic usage
    /// app.UseOidcBackChannelLogout();
    ///
    /// // With custom path and relaxed validation (not recommended for production)
    /// app.UseOidcBackChannelLogout("/auth/backchannel-logout", options => {
    ///     options.ClockSkew = TimeSpan.FromMinutes(10);
    /// });
    /// </code>
    /// </example>
    public static IApplicationBuilder UseOidcBackChannelLogout(
        this IApplicationBuilder app,
        string path = "/bff/backchannel-logout",
        Action<OidcBackChannelLogoutOptions>? configureOptions = null)
    {
        // Configure options
        var options = new OidcBackChannelLogoutOptions();
        configureOptions?.Invoke(options);

        // Fail-fast: turning off signature / issuer / audience validation lets an
        // anonymous caller terminate any session (or, with no audience check, lets
        // a token minted for another RP terminate sessions here). The settings exist
        // only as a Development debugging affordance; in any non-dev environment
        // they must be on.
        var env = app.ApplicationServices.GetService<IHostEnvironment>();
        if (env is not null && !env.IsDevelopment())
        {
            var failures = new List<string>();
            if (!options.ValidateSignature)
                failures.Add($"{nameof(OidcBackChannelLogoutOptions.ValidateSignature)}=false");
            if (!options.ValidateIssuer)
                failures.Add($"{nameof(OidcBackChannelLogoutOptions.ValidateIssuer)}=false");
            if (!options.ValidateAudience)
                failures.Add($"{nameof(OidcBackChannelLogoutOptions.ValidateAudience)}=false");

            if (failures.Count > 0)
            {
                throw new OptionsValidationException(
                    nameof(OidcBackChannelLogoutOptions),
                    typeof(OidcBackChannelLogoutOptions),
                    [$"Back-channel logout cannot run with {string.Join(", ", failures)} outside IHostEnvironment.IsDevelopment(). " +
                     "Disabling these checks lets an unauthenticated caller terminate arbitrary sessions."]);
            }
        }

        // Use middleware with path and options
        app.UseMiddleware<OidcBackChannelLogoutMiddleware>(
            Options.Create(options),
            path);

        return app;
    }

    /// <summary>
    /// Adds session administration endpoints for managing user sessions.
    /// This endpoint is opt-in and REQUIRES an authorization policy.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="path">The base path for session admin endpoints (default: "/bff/admin/sessions")</param>
    /// <param name="configureOptions">Action to configure session admin options (policy is REQUIRED)</param>
    /// <returns>The application builder for chaining</returns>
    /// <remarks>
    /// <para>
    /// This middleware provides REST endpoints for session management:
    /// <list type="bullet">
    ///   <item>GET {path}?email={email} - List all sessions for a user</item>
    ///   <item>DELETE {path}/{sessionId} - Terminate a specific session</item>
    ///   <item>DELETE {path}?email={email} - Terminate all sessions for a user</item>
    /// </list>
    /// </para>
    /// <para>
    /// Security: An authorization policy is REQUIRED. The middleware will throw at startup
    /// if RequirePolicy is not specified. This prevents accidental exposure of session
    /// management functionality.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Register the required policy first
    /// builder.Services.AddAuthorization(options => {
    ///     options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    /// });
    ///
    /// // Then enable session admin with the policy
    /// app.UseSessionAdmin("/bff/admin/sessions", options => {
    ///     options.RequirePolicy = "AdminOnly";  // Required!
    /// });
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">
    /// Thrown if RequirePolicy is not specified or the policy doesn't exist.
    /// </exception>
    public static IApplicationBuilder UseSessionAdmin(
        this IApplicationBuilder app,
        string path = "/bff/admin/sessions",
        Action<SessionAdminOptions>? configureOptions = null)
    {
        // Configure options
        var options = new SessionAdminOptions();
        configureOptions?.Invoke(options);

        // Validate that a policy is specified
        if (string.IsNullOrEmpty(options.RequirePolicy))
        {
            throw new InvalidOperationException(
                "UseSessionAdmin requires an authorization policy. " +
                "Set options.RequirePolicy to a valid policy name. " +
                "Example: options.RequirePolicy = \"AdminOnly\"");
        }

        // Record the policy requirement; OidcEndpointStartupCheck verifies it after the host
        // is built, using await against IAuthorizationPolicyProvider.GetPolicyAsync rather
        // than blocking the pipeline-build thread (which would deadlock against a genuinely
        // async custom policy provider).
        var pipelineRegistry = app.ApplicationServices.GetService<OidcEndpointPipelineRegistry>()
            ?? throw new InvalidOperationException(
                "UseSessionAdmin requires services.AddOidcEndpoints() to have been called " +
                "(or AddPortaOidcAuth, which wires it internally).");
        pipelineRegistry.RequirePolicy(options.RequirePolicy);

        // Use authorization middleware for the session admin path
        // We'll map this as a branch with authorization
        app.UseWhen(
            context => context.Request.Path.StartsWithSegments(path),
            branch =>
            {
                branch.UseAuthorization();
                branch.Use(async (context, next) =>
                {
                    // Check authorization manually since middleware doesn't have RequireAuthorization
                    var authService = context.RequestServices.GetRequiredService<IAuthorizationService>();
                    var result = await authService.AuthorizeAsync(context.User, options.RequirePolicy);

                    if (!result.Succeeded)
                    {
                        context.Response.StatusCode = context.User.Identity?.IsAuthenticated == true ? 403 : 401;
                        await context.Response.WriteAsJsonAsync(new { error = "Access denied" }, context.RequestAborted);
                        return;
                    }

                    await next();
                });
                branch.UseMiddleware<SessionAdminMiddleware>(
                    Options.Create(options),
                    path);
            });

        return app;
    }

}

/// <summary>
/// Extension methods for registering OIDC endpoint services.
/// </summary>
public static class OidcEndpointServiceExtensions
{
    /// <summary>
    /// Registers services required for OIDC endpoints.
    /// Call this if you plan to use UseOidcLogin, UseOidcLogout, UseOidcBackChannelLogout, or UseSessionAdmin.
    /// </summary>
    /// <remarks>
    /// This is automatically called by AddPortaOidcAuth(), so you only need to call this
    /// if you're using a custom authentication provider but still want the OIDC endpoints.
    /// </remarks>
    public static IServiceCollection AddOidcEndpoints(this IServiceCollection services)
    {
        // Register default options
        services.Configure<OidcLoginOptions>(_ => { });
        services.Configure<OidcLogoutOptions>(_ => { });
        services.Configure<OidcBackChannelLogoutOptions>(_ => { });
        services.Configure<SessionAdminOptions>(_ => { });

        // Data protection: AddPortaOidcAuth configures it with app-name + key-lifetime
        // via AddInfrastructure (AuthenticationServiceExtensions). This call is the
        // idempotent floor for the standalone path (custom auth provider calling
        // AddOidcEndpoints directly) so IReturnUrlProtector's IDataProtectionProvider
        // dependency always resolves; it intentionally does not reapply those settings.
        services.AddDataProtection();
        services.TryAddSingleton<IReturnUrlProtector, ReturnUrlProtector>();

        // Pipeline-build-time configuration (policy names, global-logout requests) is
        // recorded here so a hosted service can verify it asynchronously after the host
        // is built - avoids blocking sync-over-async against IAuthorizationPolicyProvider
        // and IAuthenticationSchemeProvider.
        services.TryAddSingleton<OidcEndpointPipelineRegistry>();
        services.AddHostedService<OidcEndpointStartupCheck>();

        return services;
    }
}
