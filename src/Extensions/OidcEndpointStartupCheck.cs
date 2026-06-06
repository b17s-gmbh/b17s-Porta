using b17s.Porta.Middleware;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Extensions;

/// <summary>
/// Captures what the OIDC endpoint <see cref="Microsoft.AspNetCore.Builder.IApplicationBuilder"/>
/// extensions (<c>UseSessionAdmin</c>, <c>UseOidcLogout</c>) need verified after the host starts.
///
/// These checks have to query <see cref="IAuthorizationPolicyProvider.GetPolicyAsync"/> and
/// <see cref="IAuthenticationSchemeProvider.GetSchemeAsync"/>, which are async on the abstraction.
/// The stock providers complete synchronously, so older code called <c>.GetAwaiter().GetResult()</c>
/// during pipeline build - but that deadlocks the moment a consumer supplies a genuinely async
/// provider (DB-backed policy lookup, dynamic scheme registration). Recording the requirements
/// here lets <see cref="OidcEndpointStartupCheck"/> run the queries with real <c>await</c> at
/// <see cref="IHostedService.StartAsync"/>.
/// </summary>
internal sealed class OidcEndpointPipelineRegistry
{
    private readonly HashSet<string> _requiredPolicies = new(StringComparer.Ordinal);
    private bool _globalLogoutRequested;
    private readonly Lock _gate = new();

    public void RequirePolicy(string policyName)
    {
        lock (_gate)
        {
            _requiredPolicies.Add(policyName);
        }
    }

    public void RequireGlobalLogoutPreconditions()
    {
        lock (_gate)
        {
            _globalLogoutRequested = true;
        }
    }

    public IReadOnlyCollection<string> SnapshotRequiredPolicies()
    {
        lock (_gate)
        {
            return _requiredPolicies.Count == 0
                ? Array.Empty<string>()
                : _requiredPolicies.ToArray();
        }
    }

    public bool GlobalLogoutRequested
    {
        get
        {
            lock (_gate)
            {
                return _globalLogoutRequested;
            }
        }
    }
}

/// <summary>
/// Validates OIDC endpoint preconditions after the host is built, using async APIs as intended.
///
/// Specifically:
/// <list type="bullet">
///   <item>Every authorization policy named by <c>UseSessionAdmin</c> must resolve via
///   <see cref="IAuthorizationPolicyProvider.GetPolicyAsync"/>.</item>
///   <item>If any <c>UseOidcLogout</c> call asked for global logout AND the OpenIdConnect scheme
///   is registered, the handler must have <c>SaveTokens=true</c> - otherwise <c>id_token_hint</c>
///   is missing from the end-session request and many IdPs reject it.</item>
/// </list>
/// </summary>
internal sealed class OidcEndpointStartupCheck(
    OidcEndpointPipelineRegistry registry,
    IServiceProvider services) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var requiredPolicies = registry.SnapshotRequiredPolicies();
        if (requiredPolicies.Count > 0)
        {
            var authorizationPolicyProvider = services.GetService<IAuthorizationPolicyProvider>()
                ?? throw new InvalidOperationException(
                    "UseSessionAdmin requires services.AddAuthorization(...) to be called so " +
                    "IAuthorizationPolicyProvider is available to resolve the configured policy.");

            foreach (var policyName in requiredPolicies)
            {
                var policy = await authorizationPolicyProvider.GetPolicyAsync(policyName).ConfigureAwait(false);
                if (policy is null)
                {
                    throw new InvalidOperationException(
                        $"Authorization policy '{policyName}' not found. " +
                        $"Register the policy using services.AddAuthorization(options => options.AddPolicy(\"{policyName}\", ...))");
                }
            }
        }

        if (registry.GlobalLogoutRequested)
        {
            // Skip the check if no scheme provider is wired up (the consumer is using a different
            // auth setup); other failures will surface at first request.
            var schemeProvider = services.GetService<IAuthenticationSchemeProvider>();
            if (schemeProvider is null)
            {
                return;
            }

            var oidcScheme = await schemeProvider
                .GetSchemeAsync(OpenIdConnectDefaults.AuthenticationScheme)
                .ConfigureAwait(false);

            if (oidcScheme is not null)
            {
                var options = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
                    .Get(OpenIdConnectDefaults.AuthenticationScheme);
                if (!options.SaveTokens)
                {
                    throw new OptionsValidationException(
                        nameof(OidcLogoutOptions),
                        typeof(OidcLogoutOptions),
                        [$"{nameof(OidcLogoutOptions.PerformGlobalLogout)}=true requires the OpenIdConnect handler to be configured with SaveTokens=true so that id_token_hint can be attached to the end-session request. Set SaveTokens=true on the OIDC handler or set PerformGlobalLogout=false."]);
                }
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
