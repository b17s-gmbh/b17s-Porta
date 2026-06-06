namespace b17s.Porta.Auth.Providers;

/// <summary>
/// Wraps a concrete <see cref="IAuthenticationProvider"/> registration so that
/// multiple providers can coexist in the DI container without one silently
/// displacing another.
/// </summary>
/// <remarks>
/// The registration extensions (<c>AddPortaJwtAuthentication</c>,
/// <c>AddReferenceTokenAuthentication</c>, <c>AddPortaAuthProvider&lt;T&gt;</c>)
/// register their provider under this marker interface. The DI factory for
/// <see cref="IAuthenticationProvider"/> resolves all
/// <see cref="IAuthenticationProviderRegistration"/> instances and either
/// returns the single provider directly or wraps them in a composite.
/// </remarks>
public interface IAuthenticationProviderRegistration
{
    IAuthenticationProvider Provider { get; }
}

internal sealed class AuthenticationProviderRegistration(IAuthenticationProvider provider)
    : IAuthenticationProviderRegistration
{
    public IAuthenticationProvider Provider { get; } = provider;
}
