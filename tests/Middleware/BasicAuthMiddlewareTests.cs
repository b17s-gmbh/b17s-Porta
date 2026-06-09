using System.Text;

using b17s.Porta.Tests.Fixtures;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace b17s.Porta.Tests.Middleware;

/// <summary>
/// Unit tests for BasicAuthMiddleware.
/// </summary>
public class BasicAuthMiddlewareTests
{
    private const string ValidUsername = "testuser";
    private const string ValidPassword = "testpassword";

    private readonly IConfiguration _configuration;

    public BasicAuthMiddlewareTests()
    {
        var configData = new Dictionary<string, string?>
        {
            ["BasicAuth:Username"] = ValidUsername,
            ["BasicAuth:Password"] = ValidPassword
        };

        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();
    }

    [Fact]
    public async Task InvokeAsync_WithoutBasicAuthAttribute_PassesThrough()
    {
        // Arrange
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = TestFixtures.CreateHttpContext();

        // No RequireBasicAuthAttribute on endpoint

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_WithValidCredentials_PassesThrough()
    {
        // Arrange
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithBasicAuth(ValidUsername, ValidPassword);

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.True(nextCalled);
        Assert.Equal(ValidUsername, httpContext.Items["BasicAuthUsername"]);
    }

    [Fact]
    public async Task InvokeAsync_WithInvalidUsername_Returns401()
    {
        // Arrange
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithBasicAuth("wronguser", ValidPassword);

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(401, httpContext.Response.StatusCode);
        Assert.Contains("Basic", httpContext.Response.Headers.WWWAuthenticate.ToString());
    }

    [Fact]
    public async Task InvokeAsync_WithInvalidPassword_Returns401()
    {
        // Arrange
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithBasicAuth(ValidUsername, "wrongpassword");

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(401, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WithNoAuthHeader_Returns401()
    {
        // Arrange
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithRequireBasicAuth(); // No Authorization header

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(401, httpContext.Response.StatusCode);
        Assert.Contains("Basic", httpContext.Response.Headers.WWWAuthenticate.ToString());
    }

    [Fact]
    public async Task InvokeAsync_WithBearerScheme_Returns401()
    {
        // Arrange
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithRequireBasicAuth();
        httpContext.Request.Headers.Authorization = "Bearer some-token";

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(401, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WithMalformedBase64_Returns401()
    {
        // Arrange
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithRequireBasicAuth();
        httpContext.Request.Headers.Authorization = "Basic not-valid-base64!!!";

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(401, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WithMissingColon_Returns401()
    {
        // Arrange
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithRequireBasicAuth();
        // Base64 of "usernameonly" (no colon)
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("usernameonly"));
        httpContext.Request.Headers.Authorization = $"Basic {encoded}";

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(401, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WithMissingConfiguration_Returns500()
    {
        // Arrange
        var emptyConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithBasicAuth("user", "pass");

        // Act
        await middleware.InvokeAsync(httpContext, emptyConfig);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(500, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WithBothUsernameAndPasswordWrong_Returns401()
    {
        // Arrange - Both fields wrong; verifies that constant-time comparison
        // does not short-circuit between username and password checks.
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithBasicAuth("wronguser", "wrongpassword");

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(401, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WithDifferentLengthUsername_Returns401()
    {
        // Arrange - Mismatched length username; verifies length-then-FixedTimeEquals path.
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithBasicAuth("a", ValidPassword);

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.False(nextCalled);
        Assert.Equal(401, httpContext.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_WithPasswordContainingColon_WorksCorrectly()
    {
        // Arrange
        var configWithColonPassword = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["BasicAuth:Username"] = "admin",
                ["BasicAuth:Password"] = "pass:word:with:colons"
            })
            .Build();

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithBasicAuth("admin", "pass:word:with:colons");

        // Act
        await middleware.InvokeAsync(httpContext, configWithColonPassword);

        // Assert
        Assert.True(nextCalled);
    }

    [Theory]
    [InlineData("basic")]
    [InlineData("BASIC")]
    [InlineData("bAsIc")]
    public async Task InvokeAsync_WithDifferentlyCasedScheme_PassesThrough(string scheme)
    {
        // Arrange - HTTP auth schemes are case-insensitive, so a valid credential
        // with a differently-cased "Basic" scheme must still be accepted.
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var middleware = new BasicAuthMiddleware(next, NullLogger<BasicAuthMiddleware>.Instance);
        var httpContext = CreateHttpContextWithRequireBasicAuth();
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{ValidUsername}:{ValidPassword}"));
        httpContext.Request.Headers.Authorization = $"{scheme} {credentials}";

        // Act
        await middleware.InvokeAsync(httpContext, _configuration);

        // Assert
        Assert.True(nextCalled);
        Assert.Equal(ValidUsername, httpContext.Items["BasicAuthUsername"]);
    }

    private static HttpContext CreateHttpContextWithBasicAuth(string username, string password)
    {
        var httpContext = CreateHttpContextWithRequireBasicAuth();
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
        httpContext.Request.Headers.Authorization = $"Basic {credentials}";
        return httpContext;
    }

    private static HttpContext CreateHttpContextWithRequireBasicAuth()
    {
        var httpContext = TestFixtures.CreateHttpContext();

        // Create an endpoint with RequireBasicAuthAttribute
        var endpoint = new Endpoint(
            _ => Task.CompletedTask,
            new EndpointMetadataCollection(new RequireBasicAuthAttribute()),
            "TestEndpoint");

        httpContext.SetEndpoint(endpoint);
        return httpContext;
    }
}
