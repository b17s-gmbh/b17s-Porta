using b17s.Porta.Configuration;

using Microsoft.Extensions.Configuration;

namespace b17s.Porta.Tests.Configuration;

/// <summary>
/// Trivial property-bag config holders are loaded via <c>IConfiguration.Bind</c> at startup.
/// The property surfaces have no behavior of their own, but the defaults and the binding
/// round-trip are part of the public contract — silent default changes would shift live
/// deployments that rely on omission, which is exactly the kind of regression a test can
/// pin down cheaply.
/// </summary>
public sealed class ConfigurationHoldersTests
{
    public sealed class ApiConfigurationTests
    {
        [Fact]
        public void Defaults_RequireAuthenticationIsTrue()
        {
            // RequireAuthentication defaulting to true is the "fail closed" posture — flipping
            // it to false silently would expose APIs that previously demanded a user.
            var api = new ApiConfiguration();

            Assert.True(api.RequireAuthentication);
            Assert.Equal(string.Empty, api.ApiPath);
            Assert.Equal(string.Empty, api.ApiScopes);
            Assert.Equal(string.Empty, api.ApiAudience);
            Assert.Null(api.ClientId);
            Assert.Null(api.ClientSecret);
            Assert.Null(api.TokenEndpoint);
        }

        [Fact]
        public void Bind_FromConfiguration_PopulatesAllProperties()
        {
            var source = new Dictionary<string, string?>
            {
                ["ApiPath"] = "/api/users",
                ["ApiScopes"] = "users.read",
                ["ApiAudience"] = "users-api",
                ["ClientId"] = "client-1",
                ["RequireAuthentication"] = "false",
            };
            var config = new ConfigurationBuilder().AddInMemoryCollection(source).Build();

            var bound = new ApiConfiguration();
            config.Bind(bound);

            Assert.Equal("/api/users", bound.ApiPath);
            Assert.Equal("users.read", bound.ApiScopes);
            Assert.Equal("users-api", bound.ApiAudience);
            Assert.Equal("client-1", bound.ClientId);
            Assert.False(bound.RequireAuthentication);
        }
    }
}
