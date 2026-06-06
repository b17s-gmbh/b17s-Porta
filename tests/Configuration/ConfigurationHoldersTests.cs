using b17s.Porta.Configuration;

using Microsoft.Extensions.Configuration;

namespace b17s.Porta.Tests.Configuration;

/// <summary>
/// Trivial property-bag config holders are loaded via <c>IConfiguration.Bind</c> at startup.
/// The property surfaces have no behavior of their own, but the defaults (e.g.
/// <see cref="AuthenticationConfiguration.Provider"/> = "session-based") and the binding
/// round-trip are part of the public contract — silent default changes would shift live
/// deployments that rely on omission, which is exactly the kind of regression a test can
/// pin down cheaply.
/// </summary>
public sealed class ConfigurationHoldersTests
{
    public sealed class AuthenticationConfigurationTests
    {
        [Fact]
        public void Defaults_MatchDocumentedContract()
        {
            var config = new AuthenticationConfiguration();

            Assert.Equal("session-based", config.Provider);
            Assert.Null(config.DefaultProvider);
            Assert.Empty(config.ProviderFallbackChain);
            Assert.Equal("ACCESS_TOKEN", config.TokenSessionKey);
            Assert.Equal("REFRESH_TOKEN", config.RefreshTokenSessionKey);
            Assert.Empty(config.Options);
        }

        [Fact]
        public void Bind_FromConfiguration_PopulatesAllProperties()
        {
            var source = new Dictionary<string, string?>
            {
                ["Provider"] = "reference-token",
                ["DefaultProvider"] = "session",
                ["ProviderFallbackChain:0"] = "session",
                ["ProviderFallbackChain:1"] = "reference-token",
                ["TokenSessionKey"] = "ACC",
                ["RefreshTokenSessionKey"] = "REF",
                ["Options:foo"] = "bar",
            };
            var config = new ConfigurationBuilder().AddInMemoryCollection(source).Build();

            var bound = new AuthenticationConfiguration();
            config.Bind(bound);

            Assert.Equal("reference-token", bound.Provider);
            Assert.Equal("session", bound.DefaultProvider);
            Assert.Equal(new[] { "session", "reference-token" }, bound.ProviderFallbackChain);
            Assert.Equal("ACC", bound.TokenSessionKey);
            Assert.Equal("REF", bound.RefreshTokenSessionKey);
        }

        [Fact]
        public void Setters_RoundTripValues()
        {
            var config = new AuthenticationConfiguration
            {
                Provider = "custom",
                DefaultProvider = "session",
                ProviderFallbackChain = ["a", "b"],
                TokenSessionKey = "X",
                RefreshTokenSessionKey = "Y",
                Options = new Dictionary<string, object> { ["k"] = "v" },
            };

            Assert.Equal("custom", config.Provider);
            Assert.Equal("session", config.DefaultProvider);
            Assert.Equal(["a", "b"], config.ProviderFallbackChain);
            Assert.Equal("X", config.TokenSessionKey);
            Assert.Equal("Y", config.RefreshTokenSessionKey);
            Assert.Equal("v", config.Options["k"]);
        }
    }

    public sealed class ServiceConfigurationTests
    {
        [Fact]
        public void Defaults_MatchDocumentedContract()
        {
            var config = new ServiceConfiguration();

            Assert.Equal(string.Empty, config.Name);
            Assert.Equal(string.Empty, config.Endpoint);
            Assert.Null(config.HealthCheckPath);
            Assert.Equal(TimeSpan.FromSeconds(30), config.RequestTimeout);
            Assert.Empty(config.ApiConfigurations);
        }

        [Fact]
        public void Bind_FromConfiguration_PopulatesAllProperties()
        {
            var source = new Dictionary<string, string?>
            {
                ["Name"] = "users",
                ["Endpoint"] = "https://users.internal",
                ["HealthCheckPath"] = "/health",
                ["RequestTimeout"] = "00:00:10",
                ["ApiConfigurations:0:ApiPath"] = "/api/users",
                ["ApiConfigurations:0:ApiScopes"] = "users.read",
                ["ApiConfigurations:0:ApiAudience"] = "users-api",
                ["ApiConfigurations:0:ClientId"] = "client-1",
                ["ApiConfigurations:0:RequireAuthentication"] = "false",
            };
            var config = new ConfigurationBuilder().AddInMemoryCollection(source).Build();

            var bound = new ServiceConfiguration();
            config.Bind(bound);

            Assert.Equal("users", bound.Name);
            Assert.Equal("https://users.internal", bound.Endpoint);
            Assert.Equal("/health", bound.HealthCheckPath);
            Assert.Equal(TimeSpan.FromSeconds(10), bound.RequestTimeout);
            var api = Assert.Single(bound.ApiConfigurations);
            Assert.Equal("/api/users", api.ApiPath);
            Assert.Equal("users.read", api.ApiScopes);
            Assert.Equal("users-api", api.ApiAudience);
            Assert.Equal("client-1", api.ClientId);
            Assert.False(api.RequireAuthentication);
        }

        [Fact]
        public void ApiConfiguration_Defaults_RequireAuthenticationIsTrue()
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
    }
}
