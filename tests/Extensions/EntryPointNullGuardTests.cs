using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// The biggest public entry points guard their arguments up-front so a null
/// flows into a clear <see cref="ArgumentNullException"/> at the call site
/// instead of an opaque NRE from deep inside registration or pipeline build.
/// </summary>
public class EntryPointNullGuardTests
{
    private static readonly IServiceCollection NullServices = null!;

    [Fact]
    public void AddPortaCore_NullServices_Throws()
        => Assert.Throws<ArgumentNullException>(() => NullServices.AddPortaCore());

    [Fact]
    public void AddPortaCore_NullConfiguration_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => new ServiceCollection().AddPortaCore((IConfiguration)null!));

    [Fact]
    public void AddPortaOidcAuth_NullServices_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => NullServices.AddPortaOidcAuth(_ => { }));

    [Fact]
    public void AddPortaOidcAuth_NullConfigureOptions_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => new ServiceCollection().AddPortaOidcAuth((Action<OidcAuthOptions>)null!));

    [Fact]
    public void AddPortaAuthentication_NullServices_Throws()
        => Assert.Throws<ArgumentNullException>(() => NullServices.AddPortaAuthentication());

    [Fact]
    public void AddReferenceTokenAuthentication_NullConfigureOptions_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => new ServiceCollection().AddReferenceTokenAuthentication(null!));

    [Fact]
    public void AddPortaJwtAuthentication_NullConfigureOptions_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => new ServiceCollection().AddPortaJwtAuthentication(null!));

    [Fact]
    public void AddOidcEndpoints_NullServices_Throws()
        => Assert.Throws<ArgumentNullException>(() => NullServices.AddOidcEndpoints());

    [Fact]
    public void UseOidcLogin_NullApp_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => ((IApplicationBuilder)null!).UseOidcLogin());

    [Fact]
    public void UseOidcLogout_NullApp_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => ((IApplicationBuilder)null!).UseOidcLogout());

    [Fact]
    public void UseOidcBackChannelLogout_NullApp_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => ((IApplicationBuilder)null!).UseOidcBackChannelLogout());

    [Fact]
    public void UseSessionAdmin_NullApp_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => ((IApplicationBuilder)null!).UseSessionAdmin());

    [Fact]
    public void UseOidcLogin_EmptyPath_Throws()
    {
        var app = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());

        Assert.Throws<ArgumentException>(() => app.UseOidcLogin(path: ""));
    }

    [Fact]
    public void UseSessionAdmin_EmptyPath_Throws()
    {
        var app = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());

        Assert.Throws<ArgumentException>(() => app.UseSessionAdmin(path: ""));
    }
}
