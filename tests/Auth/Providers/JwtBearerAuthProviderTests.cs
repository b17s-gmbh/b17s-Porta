using System.Security.Claims;

using b17s.Porta.Auth.Providers;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

using Moq;

namespace b17s.Porta.Tests.Auth.Providers;

public class JwtBearerAuthProviderTests
{
    [Fact]
    public async Task GetAuthContextAsync_WhenAuthenticateFails_ReturnsUnauthenticated()
    {
        var authServiceMock = new Mock<IAuthenticationService>();
        authServiceMock.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), "Bearer"))
            .ReturnsAsync(AuthenticateResult.Fail("Invalid token"));

        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddSingleton(authServiceMock.Object);
        var sp = services.BuildServiceProvider();

        var context = new DefaultHttpContext { RequestServices = sp };

        var provider = new JwtBearerAuthProvider(NullLogger<JwtBearerAuthProvider>.Instance);
        var result = await provider.GetAuthContextAsync(context, TestContext.Current.CancellationToken);

        Assert.False(result.IsAuthenticated);
        Assert.Null(result.AccessToken);
    }

    [Fact]
    public async Task GetAuthContextAsync_WhenAuthenticateSucceedsButNoSavedToken_ReturnsUnauthenticated()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", "user1") }, "Bearer"));
        var authServiceMock = new Mock<IAuthenticationService>();
        authServiceMock.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), "Bearer"))
            .ReturnsAsync(AuthenticateResult.Success(new AuthenticationTicket(principal, "Bearer")));

        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddSingleton(authServiceMock.Object);
        var sp = services.BuildServiceProvider();

        var context = new DefaultHttpContext { RequestServices = sp };

        var provider = new JwtBearerAuthProvider(NullLogger<JwtBearerAuthProvider>.Instance);
        var result = await provider.GetAuthContextAsync(context, TestContext.Current.CancellationToken);

        Assert.False(result.IsAuthenticated);
        Assert.Null(result.AccessToken);
    }

    [Fact]
    public async Task GetAuthContextAsync_WhenAuthenticateSucceedsAndHasSavedToken_ReturnsAuthenticatedContext()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", "user1") }, "Bearer"));
        var properties = new AuthenticationProperties();
        properties.StoreTokens(new[] { new AuthenticationToken { Name = "access_token", Value = "my-raw-jwt" } });

        var ticket = new AuthenticationTicket(principal, properties, "Bearer");

        var authServiceMock = new Mock<IAuthenticationService>();
        authServiceMock.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), "Bearer"))
            .ReturnsAsync(AuthenticateResult.Success(ticket));

        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddSingleton(authServiceMock.Object);
        var sp = services.BuildServiceProvider();

        var context = new DefaultHttpContext { RequestServices = sp };

        var provider = new JwtBearerAuthProvider(NullLogger<JwtBearerAuthProvider>.Instance);
        var result = await provider.GetAuthContextAsync(context, TestContext.Current.CancellationToken);

        Assert.True(result.IsAuthenticated);
        Assert.Equal("my-raw-jwt", result.AccessToken);
        Assert.Equal("user1", result.Claims["sub"][0]);
    }

    [Fact]
    public async Task GetAuthContextAsync_MultipleClaimsOfSameType_AllValuesPreserved()
    {
        // Regression: a Dictionary<string,string> claim store silently dropped all but the
        // last value of a repeated claim type (e.g. multiple role claims), collapsing
        // role-based authorization. The multi-valued store must keep every value.
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            new[]
            {
                new Claim("sub", "user1"),
                new Claim("role", "admin"),
                new Claim("role", "ops"),
                new Claim("role", "reader"),
            }, "Bearer"));
        var properties = new AuthenticationProperties();
        properties.StoreTokens(new[] { new AuthenticationToken { Name = "access_token", Value = "my-raw-jwt" } });

        var authServiceMock = new Mock<IAuthenticationService>();
        authServiceMock.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), "Bearer"))
            .ReturnsAsync(AuthenticateResult.Success(new AuthenticationTicket(principal, properties, "Bearer")));

        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddSingleton(authServiceMock.Object);
        var sp = services.BuildServiceProvider();

        var context = new DefaultHttpContext { RequestServices = sp };

        var provider = new JwtBearerAuthProvider(NullLogger<JwtBearerAuthProvider>.Instance);
        var result = await provider.GetAuthContextAsync(context, TestContext.Current.CancellationToken);

        Assert.True(result.IsAuthenticated);
        Assert.Equal(new[] { "admin", "ops", "reader" }, result.Claims["role"]);
    }
}
