using System.Text.Encodings.Web;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Providers;
using b17s.Porta.Extensions;
using b17s.Porta.Services;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Auth.Providers;

/// <summary>
/// Multi-frontend composition: the <c>PortaReferenceToken</c> scheme must register additively and
/// must NOT clobber another default scheme (e.g. the cookie default set by <c>AddPortaAuthentication</c>),
/// so a BFF can accept browser (cookie/OIDC), JWT, and opaque-token callers at once.
/// </summary>
public sealed class PortaReferenceTokenSchemeCompositionTests
{
    [Fact]
    public void Standalone_ReferenceTokenScheme_BecomesDefault()
    {
        var services = NewServices();
        services.AddPortaReferenceTokenScheme(o => o.Authority = "https://idp.test");

        var options = services.BuildServiceProvider()
            .GetRequiredService<IOptions<AuthenticationOptions>>().Value;

        Assert.Equal(PortaReferenceTokenDefaults.AuthenticationScheme, options.DefaultScheme);
    }

    [Theory]
    [InlineData(true)]   // reference-token registered AFTER the cookie default
    [InlineData(false)]  // reference-token registered BEFORE the cookie default
    public async Task AlongsideCookieDefault_DoesNotClobberDefault_AndStaysRegistered(bool referenceTokenLast)
    {
        var services = NewServices();

        void AddCookieDefault() => services
            .AddAuthentication(o => o.DefaultScheme = "Cookies")   // mirrors AddPortaAuthentication
            .AddScheme<AuthenticationSchemeOptions, StubHandler>("Cookies", _ => { });
        void AddReferenceToken() => services.AddPortaReferenceTokenScheme(o => o.Authority = "https://idp.test");

        if (referenceTokenLast) { AddCookieDefault(); AddReferenceToken(); }
        else { AddReferenceToken(); AddCookieDefault(); }

        var provider = services.BuildServiceProvider();

        // The cookie default survives regardless of registration order...
        var options = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;
        Assert.Equal("Cookies", options.DefaultScheme);

        // ...and the reference-token scheme is still available for per-request selection.
        var schemeProvider = provider.GetRequiredService<IAuthenticationSchemeProvider>();
        Assert.NotNull(await schemeProvider.GetSchemeAsync(PortaReferenceTokenDefaults.AuthenticationScheme));
        Assert.NotNull(await schemeProvider.GetSchemeAsync("Cookies"));
    }

    [Fact]
    public void Standalone_ReferenceTokenScheme_RegistersDiscoveryService_SoIntrospectionServiceResolves()
    {
        // Regression: ReferenceTokenService takes IDiscoveryService in its constructor, but only the
        // session/OIDC path used to register that service. A reference-token-only BFF therefore had an
        // unsatisfiable singleton and failed DI validation at startup. The scheme (which promises "no
        // consumer-side auth code") must register discovery itself.
        // NOTE: unlike the other tests here, this one does NOT register a FakeIntrospector - that fake is
        // exactly what hid this gap, because it shadowed the real ReferenceTokenService graph.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDistributedMemoryCache();

        services.AddPortaReferenceTokenScheme(o => o.Authority = "https://idp.test");

        var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });

        // The real introspection service - which depends on IDiscoveryService - constructs cleanly.
        var introspector = provider.GetRequiredService<IReferenceTokenService>();
        Assert.IsType<ReferenceTokenService>(introspector);
        Assert.NotNull(provider.GetRequiredService<IDiscoveryService>());
    }

    private static ServiceCollection NewServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDistributedMemoryCache();
        services.AddSingleton<IReferenceTokenService>(new FakeIntrospector());
        return services;
    }

    private sealed class FakeIntrospector : IReferenceTokenService
    {
        public Task<ReferenceTokenIntrospectionResult?> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
            => Task.FromResult<ReferenceTokenIntrospectionResult?>(new ReferenceTokenIntrospectionResult { IsActive = false });
    }

    private sealed class StubHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());
    }
}
