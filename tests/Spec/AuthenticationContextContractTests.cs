using b17s.Porta.Auth.Providers;

namespace b17s.Porta.Tests.Spec;

/// <summary>
/// Spec §2.7 — AuthenticationContext.IsAuthenticated is exactly !IsNullOrEmpty(AccessToken),
/// and Unauthenticated() yields an empty, unauthenticated context.
/// </summary>
public class AuthenticationContextContractTests
{
    [Fact]
    public void IsAuthenticated_TrueWhenAccessTokenPresent()
    {
        var ctx = new AuthenticationContext { AccessToken = "header.payload.sig" };

        Assert.True(ctx.IsAuthenticated);
    }

    [Fact]
    public void IsAuthenticated_FalseWhenAccessTokenNull()
    {
        var ctx = new AuthenticationContext { AccessToken = null };

        Assert.False(ctx.IsAuthenticated);
    }

    [Fact]
    public void IsAuthenticated_FalseWhenAccessTokenEmpty()
    {
        var ctx = new AuthenticationContext { AccessToken = "" };

        Assert.False(ctx.IsAuthenticated);
    }

    [Fact]
    public void Unauthenticated_IsNotAuthenticated()
    {
        var ctx = AuthenticationContext.Unauthenticated();

        Assert.False(ctx.IsAuthenticated);
        Assert.True(string.IsNullOrEmpty(ctx.AccessToken));
    }
}
