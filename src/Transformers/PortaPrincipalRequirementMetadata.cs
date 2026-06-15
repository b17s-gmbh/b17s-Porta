namespace b17s.Porta.Transformers;

/// <summary>
/// Endpoint metadata stamped by the Porta builders at <c>Build()</c> recording whether the endpoint
/// resolved to "requires an authenticated principal" (i.e. it stamps <c>RequireAuthorization()</c>
/// rather than <c>AllowAnonymous()</c>). The startup check uses it to detect the silent gap where a
/// Porta endpoint needs a populated <c>HttpContext.User</c> but no ASP.NET authentication scheme is
/// registered to provide one.
/// </summary>
internal sealed class PortaPrincipalRequirementMetadata(bool requiresAuthenticatedPrincipal)
{
    /// <summary>Whether this endpoint requires <c>HttpContext.User</c> to be authenticated.</summary>
    public bool RequiresAuthenticatedPrincipal { get; } = requiresAuthenticatedPrincipal;
}
