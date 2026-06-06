using b17s.Porta.Transformers;

namespace b17s.Porta.Tests.Spec;

/// <summary>
/// Spec §2.8 — BackendAuthPolicies constants and RequiresUserIdentity helper.
/// </summary>
public class BackendAuthPoliciesContractTests
{
    [Fact]
    public void Constants_HaveSpecifiedStringValues()
    {
        Assert.Equal("None", BackendAuthPolicies.None);
        Assert.Equal("BasicAuth", BackendAuthPolicies.BasicAuth);
        Assert.Equal("BearerToken", BackendAuthPolicies.BearerToken);
        Assert.Equal("TokenExchange", BackendAuthPolicies.TokenExchange);
    }

    [Fact]
    public void RequiresUserIdentity_TrueOnlyForBearerAndTokenExchange()
    {
        Assert.True(BackendAuthPolicies.RequiresUserIdentity(BackendAuthPolicies.BearerToken));
        Assert.True(BackendAuthPolicies.RequiresUserIdentity(BackendAuthPolicies.TokenExchange));

        Assert.False(BackendAuthPolicies.RequiresUserIdentity(BackendAuthPolicies.None));
        Assert.False(BackendAuthPolicies.RequiresUserIdentity(BackendAuthPolicies.BasicAuth));
    }
}
