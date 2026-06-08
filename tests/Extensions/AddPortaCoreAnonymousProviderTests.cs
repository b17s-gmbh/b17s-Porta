using b17s.Porta.Auth.Providers;
using b17s.Porta.Extensions;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// Regression tests for the documented "Minimal Setup (No Auth)" path (README): an
/// <see cref="PortaServiceExtensions.AddPortaCore(IServiceCollection)"/>-only application
/// must be able to serve anonymous endpoints. The transformer / raw-forward handlers always
/// resolve <see cref="IAuthenticationProvider"/>, so a factory that threw when zero providers
/// were registered turned the documented no-auth setup into a request-time 500.
/// </summary>
public sealed class AddPortaCoreAnonymousProviderTests
{
    [Fact]
    public void IAuthenticationProvider_Resolves_WhenNoProviderRegistered()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddPortaCore();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        // Before the fix this threw InvalidOperationException ("No authentication provider
        // registered.") - the same exception that surfaced as a 500 on anonymous endpoints.
        var authProvider = scope.ServiceProvider.GetRequiredService<IAuthenticationProvider>();
        Assert.NotNull(authProvider);
    }

    [Fact]
    public async Task GetAuthContextAsync_ReturnsUnauthenticated_WhenNoProviderRegistered()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddPortaCore();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var authProvider = scope.ServiceProvider.GetRequiredService<IAuthenticationProvider>();

        // An AddPortaCore-only app has no credential surface, so the composite must produce an
        // unauthenticated context rather than throwing. Endpoints that actually require auth are
        // still gated by the principal check in the endpoint handlers (which 401s), not here.
        var context = await authProvider.GetAuthContextAsync(
            new DefaultHttpContext(), TestContext.Current.CancellationToken);

        Assert.False(context.IsAuthenticated);
    }
}
