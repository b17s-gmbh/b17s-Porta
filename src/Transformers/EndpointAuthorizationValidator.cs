namespace b17s.Porta.Transformers;

/// <summary>
/// Throws if a transformer endpoint has at least one backend that requires user
/// identity (forwarded user token, token exchange, or a backend-auth policy
/// that names a user) but the endpoint allows anonymous access. Catches a
/// configuration mistake early at startup rather than at first request.
/// </summary>
internal static class EndpointAuthorizationValidator
{
    /// <summary>
    /// Throws if the named backend-auth policy is not registered. Catches typos
    /// like <c>WithBackendAuth("BAsicAUth")</c> at build time so that requests
    /// can never silently fall back to forwarding the user's bearer token.
    /// </summary>
    public static void ValidatePolicyRegistered(
        string? policy,
        IBackendAuthHandlerRegistry? registry,
        string context)
    {
        if (string.IsNullOrEmpty(policy) || registry == null)
        {
            return;
        }

        if (registry.GetHandler(policy) == null)
        {
            var registered = string.Join(", ", registry.GetRegisteredPolicies());
            throw new InvalidOperationException(
                $"Unknown backend auth policy '{policy}' for {context}. " +
                $"Registered policies: [{registered}]. " +
                $"Check for typos or register the handler with services.AddPortaAuthHandler<T>().");
        }
    }


    public static void Validate(
        string? routePattern,
        string? backendAuthPolicy,
        bool useTokenExchange,
        string? tokenExchangeAudience,
        NamedBackendEndpoints namedBackends,
        bool effectiveRequireAuth,
        IBackendAuthHandlerRegistry? authHandlerRegistry = null,
        Type? transformerType = null)
    {
        ValidatePolicyRegistered(backendAuthPolicy, authHandlerRegistry, $"endpoint '{routePattern}'");
        foreach (var name in namedBackends.Names)
        {
            if (namedBackends.TryGet(name, out var endpoint) && endpoint != null)
            {
                ValidatePolicyRegistered(
                    endpoint.BackendAuthPolicy,
                    authHandlerRegistry,
                    $"endpoint '{routePattern}' backend '{endpoint.Name}'");
            }
        }

        var backendsRequiringIdentity = new List<string>();

        if (transformerType?.IsDefined(typeof(RequiresAuthenticationAttribute), inherit: true) == true)
        {
            backendsRequiringIdentity.Add($"transformer {transformerType.Name} ([RequiresAuthentication])");
        }

        if (BackendAuthPolicies.RequiresUserIdentity(backendAuthPolicy))
        {
            backendsRequiringIdentity.Add($"ToBackend (policy: {backendAuthPolicy})");
        }

        if (useTokenExchange)
        {
            backendsRequiringIdentity.Add($"ToBackend (token exchange: {tokenExchangeAudience})");
        }

        foreach (var name in namedBackends.Names)
        {
            if (namedBackends.TryGet(name, out var endpoint) && endpoint != null)
            {
                if (endpoint.ForwardUserToken
                    || BackendAuthPolicies.RequiresUserIdentity(endpoint.BackendAuthPolicy)
                    || endpoint.UseTokenExchange)
                {
                    backendsRequiringIdentity.Add($"'{endpoint.Name}' (policy: {endpoint.BackendAuthPolicy ?? "None"})");
                }
            }
        }

        if (backendsRequiringIdentity.Count > 0 && !effectiveRequireAuth)
        {
            throw new InvalidOperationException(
                $"Endpoint '{routePattern}' requires user identity but AllowAnonymous() was called. " +
                $"Remove AllowAnonymous() or change auth requirements. " +
                $"Sources requiring identity: [{string.Join(", ", backendsRequiringIdentity)}]");
        }
    }
}
