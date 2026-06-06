using b17s.Porta.Transformers;

namespace b17s.Porta.Tests.Spec;

/// <summary>
/// Spec §2.5 — NamedBackendEndpoint defaults, FromTuple factory, fluent builders,
/// and the NamedBackendEndpoints name-keyed collection.
/// </summary>
public class NamedBackendEndpointContractTests
{
    private static NamedBackendEndpoint Sample() =>
        new() { Name = "orders", Method = "GET", UrlTemplate = "https://api.example/orders/{id}" };

    [Fact]
    public void Defaults_AreAsSpecified()
    {
        var ep = Sample();

        Assert.Equal("orders", ep.Name);
        Assert.Equal("GET", ep.Method);
        Assert.Equal("https://api.example/orders/{id}", ep.UrlTemplate);
        Assert.False(ep.UseTokenExchange);
        Assert.False(ep.ForwardUserToken);
        Assert.False(ep.EnableRetries);
        Assert.Equal(3, ep.MaxRetryAttempts);
        Assert.Null(ep.BackendAuthPolicy);
        Assert.Null(ep.TokenExchangeAudience);
        Assert.Null(ep.Timeout);
    }

    [Fact]
    public void FromTuple_PopulatesCoreFields()
    {
        var ep = NamedBackendEndpoint.FromTuple("orders", "POST", "https://api.example/orders");

        Assert.Equal("orders", ep.Name);
        Assert.Equal("POST", ep.Method);
        Assert.Equal("https://api.example/orders", ep.UrlTemplate);
    }

    [Fact]
    public void FromTuple_AppliesAuthPolicy()
    {
        var ep = NamedBackendEndpoint.FromTuple("orders", "GET", "https://api.example/orders", BackendAuthPolicies.BasicAuth);

        Assert.Equal(BackendAuthPolicies.BasicAuth, ep.BackendAuthPolicy);
    }

    // Fluent builders (§2.5) hang off the (name, method, url) tuple and produce a NamedBackendEndpoint.

    private static (string Name, string Method, string Url) Tuple() =>
        ("orders", "GET", "https://api.example/orders/{id}");

    [Fact]
    public void WithAuth_SetsPolicy()
    {
        var ep = Tuple().WithAuth(BackendAuthPolicies.BearerToken);

        Assert.Equal("orders", ep.Name);
        Assert.Equal(BackendAuthPolicies.BearerToken, ep.BackendAuthPolicy);
    }

    [Fact]
    public void WithUserToken_SetsForwardUserToken()
    {
        var ep = Tuple().WithUserToken();

        Assert.True(ep.ForwardUserToken);
    }

    [Fact]
    public void WithTokenExchange_SetsFlagAndAudience()
    {
        var ep = Tuple().WithTokenExchange("api://downstream");

        Assert.True(ep.UseTokenExchange);
        Assert.Equal("api://downstream", ep.TokenExchangeAudience);
    }

    [Fact]
    public void WithTimeout_SetsTimeout()
    {
        var ep = Tuple().WithTimeout(TimeSpan.FromSeconds(7));

        Assert.Equal(TimeSpan.FromSeconds(7), ep.Timeout);
    }

    [Fact]
    public void WithRetries_EnablesAndSetsMaxAttempts()
    {
        var ep = Tuple().WithRetries(5);

        Assert.True(ep.EnableRetries);
        Assert.Equal(5, ep.MaxRetryAttempts);
    }

    // NamedBackendEndpointsBuilder (§2.5) backs the ToBackends(configure => ...) overload: verb methods
    // add a backend and per-backend modifiers mutate the most recently added one.

    private static NamedBackendEndpoint[] BuildVia(Action<NamedBackendEndpointsBuilder> configure)
    {
        var builder = new NamedBackendEndpointsBuilder();
        configure(builder);
        return builder.Build();
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    public void CollectionBuilder_VerbMethods_SetMethodNameAndUrl(string verb)
    {
        var built = BuildVia(b =>
        {
            switch (verb)
            {
                case "GET": b.ToGet("orders", "https://api.example/orders"); break;
                case "POST": b.ToPost("orders", "https://api.example/orders"); break;
                case "PUT": b.ToPut("orders", "https://api.example/orders"); break;
                case "DELETE": b.ToDelete("orders", "https://api.example/orders"); break;
                case "PATCH": b.ToPatch("orders", "https://api.example/orders"); break;
            }
        });

        var ep = Assert.Single(built);
        Assert.Equal("orders", ep.Name);
        Assert.Equal(verb, ep.Method);
        Assert.Equal("https://api.example/orders", ep.UrlTemplate);
    }

    [Fact]
    public void CollectionBuilder_AddsBackendsInOrder()
    {
        var built = BuildVia(b => b
            .ToGet("UserInfo", "https://api.example/userinfo")
            .ToPost("Orders", "https://api.example/orders"));

        Assert.Collection(built,
            ep => { Assert.Equal("UserInfo", ep.Name); Assert.Equal("GET", ep.Method); },
            ep => { Assert.Equal("Orders", ep.Name); Assert.Equal("POST", ep.Method); });
    }

    [Fact]
    public void CollectionBuilder_ModifiersApplyToMostRecentBackendOnly()
    {
        // WithAuth after ToGet must land on UserInfo; WithTokenExchange+WithRetries after ToPost must
        // land on Orders and leave UserInfo untouched.
        var built = BuildVia(b => b
            .ToGet("UserInfo", "https://api.example/userinfo").WithAuth(BackendAuthPolicies.BearerToken)
            .ToPost("Orders", "https://api.example/orders").WithTokenExchange("order-api").WithRetries(5));

        var userInfo = Assert.Single(built, e => e.Name == "UserInfo");
        Assert.Equal(BackendAuthPolicies.BearerToken, userInfo.BackendAuthPolicy);
        Assert.False(userInfo.UseTokenExchange);
        Assert.False(userInfo.EnableRetries);

        var orders = Assert.Single(built, e => e.Name == "Orders");
        Assert.Equal(BackendAuthPolicies.TokenExchange, orders.BackendAuthPolicy);
        Assert.True(orders.UseTokenExchange);
        Assert.Equal("order-api", orders.TokenExchangeAudience);
        Assert.True(orders.EnableRetries);
        Assert.Equal(5, orders.MaxRetryAttempts);
    }

    [Fact]
    public void CollectionBuilder_WithUserToken_SetsBearerAndForwardFlag()
    {
        var built = BuildVia(b => b
            .ToGet("Internal", "https://api.example/internal").WithUserToken());

        var ep = Assert.Single(built);
        Assert.Equal(BackendAuthPolicies.BearerToken, ep.BackendAuthPolicy);
        Assert.True(ep.ForwardUserToken);
    }

    [Fact]
    public void CollectionBuilder_ModifierBeforeAnyBackend_Throws()
    {
        // A modifier with nothing to attach to is a programming error; fail loud rather than silently
        // dropping the call.
        Assert.Throws<InvalidOperationException>(() =>
            new NamedBackendEndpointsBuilder().WithAuth(BackendAuthPolicies.BearerToken));
    }

    // ----- NamedBackendEndpoints collection -----

    [Fact]
    public void Collection_AddGetTryGetNamesCount()
    {
        var ep = Sample();
        var endpoints = new NamedBackendEndpoints();
        endpoints.Add(ep);

        Assert.Equal(1, endpoints.Count);
        Assert.Contains("orders", endpoints.Names);

        Assert.Same(ep, endpoints.Get("orders"));

        Assert.True(endpoints.TryGet("orders", out var got));
        Assert.Same(ep, got);

        Assert.False(endpoints.TryGet("missing", out _));
    }

    [Fact]
    public void Collection_Get_ThrowsWhenAbsent()
    {
        var endpoints = new NamedBackendEndpoints();

        Assert.ThrowsAny<Exception>(() => endpoints.Get("missing"));
    }
}
