using System.Net.Http.Headers;
using System.Text;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Transformers;

/// <summary>
/// Built-in backend auth handler that adds no authentication.
/// Use for public APIs that don't require authentication.
/// </summary>
public sealed class NoneAuthHandler : IBackendAuthHandler
{
    /// <inheritdoc/>
    public string PolicyName => BackendAuthPolicies.None;

    /// <inheritdoc/>
    public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
        // No authentication applied
        => Task.CompletedTask;
}

/// <summary>
/// Built-in backend auth handler that forwards the user's Bearer token.
/// Use for backends that accept the same OAuth tokens as the BFF.
/// </summary>
public sealed class BearerTokenAuthHandler(ILogger<BearerTokenAuthHandler> logger) : IBackendAuthHandler
{
    /// <inheritdoc/>
    public string PolicyName => BackendAuthPolicies.BearerToken;

    /// <inheritdoc/>
    public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
    {
        if (!string.IsNullOrEmpty(context.AccessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
            logger.LogDebug("Forwarding Bearer token to backend");
        }
        else
        {
            logger.LogWarning("BearerToken policy requested but no access token available");
        }

        return Task.CompletedTask;
    }
}

/// <summary>
/// Built-in backend auth handler that applies HTTP Basic authentication using
/// credentials configured via <see cref="BackendServiceOptions"/>.
/// Per-backend credentials are resolved from <see cref="BackendServiceOptions.Backends"/>
/// using <see cref="BackendRequest.BackendName"/>. A request that names a backend with no
/// matching entry fails closed (no credentials sent) unless
/// <see cref="BackendServiceOptions.AllowGlobalBasicAuthFallback"/> is set; an unnamed request
/// always uses the global <see cref="BackendServiceOptions.BasicAuth"/> default.
/// </summary>
public sealed class BasicAuthHandler(
    IOptions<BackendServiceOptions> options,
    ILogger<BasicAuthHandler> logger) : IBackendAuthHandler
{
    private readonly BackendServiceOptions _options = options.Value;

    /// <inheritdoc/>
    public string PolicyName => BackendAuthPolicies.BasicAuth;

    /// <inheritdoc/>
    public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
    {
        var backendName = context.BackendRequest.BackendName;
        var credentials = ResolveCredentials(backendName);

        if (!string.IsNullOrEmpty(credentials.Username))
        {
            if (string.IsNullOrEmpty(credentials.Password))
            {
                // Still sent (some backends accept blank passwords), but almost always a
                // misconfiguration - surface it rather than silently shipping "user:".
                logger.LogWarning(
                    "BasicAuth for backend '{Backend}' has a username but an empty password",
                    backendName ?? "<default>");
            }

            var encoded = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{credentials.Username}:{credentials.Password}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", encoded);
            logger.LogDebug("Adding Basic Auth to backend request for backend '{Backend}'", backendName ?? "<default>");
        }
        else
        {
            logger.LogWarning(
                "BasicAuth policy configured but credentials not set for backend '{Backend}'",
                backendName ?? "<default>");
        }

        return Task.CompletedTask;
    }

    private BasicAuthOptions ResolveCredentials(string? backendName)
    {
        // Per-backend credentials always win.
        if (!string.IsNullOrEmpty(backendName)
            && _options.Backends.TryGetValue(backendName, out var perBackend)
            && !string.IsNullOrEmpty(perBackend.Username))
        {
            return perBackend;
        }

        // A request that explicitly names a backend but has no matching per-backend entry is
        // ambiguous. Falling back to the global default would forward credentials that may belong
        // to a different host. Fail closed unless the consumer opted into the shared-global fallback.
        if (!string.IsNullOrEmpty(backendName) && !_options.AllowGlobalBasicAuthFallback)
        {
            logger.LogWarning(
                "BasicAuth requested for backend '{Backend}' which has no per-backend credentials; " +
                "not falling back to the global default (set BackendServiceOptions.AllowGlobalBasicAuthFallback " +
                "to true to allow this). No Authorization header will be sent.",
                backendName);
            return new BasicAuthOptions();
        }

        // No backend name (single-backend / default config) or fallback explicitly allowed.
        return _options.BasicAuth;
    }
}

/// <summary>
/// Built-in backend auth handler that exchanges the user's access token (RFC 8693)
/// for a backend-specific token and applies it as a Bearer credential.
/// </summary>
/// <remarks>
/// Audience resolution order:
/// <list type="number">
/// <item><description><c>BackendRequest.TokenExchangeAudience</c> (set via <c>WithTokenExchange(audience)</c>)</description></item>
/// <item><description><c>BackendServiceOptions.TokenExchangeAudiences[BackendName]</c> (per-backend default)</description></item>
/// <item><description><c>BackendServiceOptions.DefaultTokenExchangeAudience</c> (global default)</description></item>
/// </list>
/// The handler requires <see cref="IApiTokenService"/> to be registered - this happens automatically
/// when <c>AddPortaAuthentication()</c> or <c>AddPortaOidcAuth()</c> is called. Without it, the handler
/// throws and <see cref="BackendCaller"/> converts the failure into a 401 backend-auth error.
/// <para>
/// The underlying <see cref="ITokenExchangeService"/> needs the IdP token endpoint plus client
/// credentials. The handler resolves the token endpoint from the OIDC discovery document at
/// <see cref="SessionAuthenticationConfiguration.Authority"/> and the client id/secret from the same
/// session configuration, so endpoints that merely declare the policy (e.g. <c>.WithTokenExchange(audience)</c>)
/// work without restating the IdP wiring. When <see cref="IDiscoveryService"/> or the session
/// configuration are not registered (Porta core used without authentication), it falls back to whatever
/// the consumer pre-populated on the <see cref="ApiConfiguration"/>.
/// </para>
/// </remarks>
public sealed class TokenExchangeAuthHandler(
    IOptions<BackendServiceOptions> options,
    ILogger<TokenExchangeAuthHandler> logger,
    IHttpContextAccessor? httpContextAccessor = null,
    IDiscoveryService? discoveryService = null,
    IOptions<SessionAuthenticationConfiguration>? sessionConfig = null) : IBackendAuthHandler
{
    private readonly BackendServiceOptions _options = options.Value;
    private readonly SessionAuthenticationConfiguration? _sessionConfig = sessionConfig?.Value;

    /// <inheritdoc/>
    public string PolicyName => BackendAuthPolicies.TokenExchange;

    /// <inheritdoc/>
    public async Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
    {
        // Static configuration / dependency failures below throw BackendAuthConfigurationException
        // (a 5xx-class operator problem) so BackendCaller does not mislabel them as a user 401.
        var httpContext = httpContextAccessor?.HttpContext
            ?? throw new BackendAuthConfigurationException("Token exchange requested but no HttpContext is available.");

        // This handler is a singleton; resolve the scoped IApiTokenService from the current request
        // scope rather than the constructor, which would be a captive dependency.
        var apiTokenService = httpContext.RequestServices?.GetService<IApiTokenService>()
            ?? throw new BackendAuthConfigurationException(
                "Token exchange requested but IApiTokenService is not registered. " +
                "Call AddPortaAuthentication() or AddPortaOidcAuth() to enable token exchange.");

        var backendRequest = context.BackendRequest;
        var audience = ResolveAudience(backendRequest);
        if (string.IsNullOrEmpty(audience))
        {
            throw new BackendAuthConfigurationException(
                "Token exchange policy was selected but no audience is configured. " +
                "Set one via .WithTokenExchange(audience), BackendServiceOptions.TokenExchangeAudiences[backendName], " +
                "or BackendServiceOptions.DefaultTokenExchangeAudience.");
        }

        var apiConfig = new ApiConfiguration
        {
            ApiAudience = audience,
            ApiPath = backendRequest.Url,
            ClientId = _sessionConfig?.ClientId,
            ClientSecret = _sessionConfig?.ClientSecret,
            TokenEndpoint = await ResolveTokenEndpointAsync(context.CancellationToken)
        };

        var accessToken = await apiTokenService.GetApiTokenAsync(
            httpContext,
            apiConfig,
            context.AccessToken,
            context.CancellationToken);

        if (string.IsNullOrEmpty(accessToken))
        {
            // Fail closed - forwarding "Authorization: Bearer " (empty) is treated as
            // anonymous by many backends and silently downgrades the user's permissions.
            throw new InvalidOperationException("Token exchange failed to produce a token.");
        }

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        logger.LogDebug("Applied token exchange auth for audience: {Audience}", audience);
    }

    private string? ResolveAudience(BackendRequest request)
    {
        if (!string.IsNullOrEmpty(request.TokenExchangeAudience))
        {
            return request.TokenExchangeAudience;
        }

        if (!string.IsNullOrEmpty(request.BackendName)
            && _options.TokenExchangeAudiences.TryGetValue(request.BackendName, out var perBackend)
            && !string.IsNullOrEmpty(perBackend))
        {
            return perBackend;
        }

        return _options.DefaultTokenExchangeAudience;
    }

    /// <summary>
    /// Resolves the IdP token endpoint from the OIDC discovery document at the configured
    /// authority. Returns <c>null</c> when discovery or the session configuration is unavailable,
    /// or the authority is unset - leaving <see cref="ApiConfiguration.TokenEndpoint"/> empty so
    /// <see cref="ITokenExchangeService"/> surfaces the standard "token endpoint must be configured"
    /// failure rather than silently forwarding an unexchanged token.
    /// </summary>
    private async Task<string?> ResolveTokenEndpointAsync(CancellationToken cancellationToken)
    {
        var authority = _sessionConfig?.Authority;
        if (discoveryService is null || string.IsNullOrEmpty(authority))
        {
            return null;
        }

        var configuration = await discoveryService.GetConfigurationAsync(authority, cancellationToken);
        return configuration?.TokenEndpoint;
    }
}

/// <summary>
/// Thrown by a backend auth handler when it cannot apply authentication because of a server-side
/// configuration or dependency problem (e.g. token exchange selected with no audience configured, or
/// <c>IApiTokenService</c> not registered) - as opposed to a genuine rejection of the user's
/// credentials. <see cref="BackendCaller"/> maps this to <see cref="BackendErrorType.ConfigurationError"/>
/// (a 5xx-class result) so operators aren't misled into chasing a user-auth failure.
/// Derives from <see cref="InvalidOperationException"/> for backwards compatibility with callers that
/// already catch that type.
/// </summary>
public sealed class BackendAuthConfigurationException(string message) : InvalidOperationException(message);
