using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;

namespace b17s.Porta.Tests.Fixtures;

/// <summary>
/// Factory for creating test fixtures with sensible defaults.
/// </summary>
public static class TestFixtures
{
    /// <summary>
    /// Creates an authenticated AuthenticationContext with the specified claims.
    /// </summary>
    public static AuthenticationContext CreateAuthContext(
        string? userId = "12345",
        string? accessToken = "test-access-token",
        Dictionary<string, string>? additionalClaims = null)
    {
        var claims = new Dictionary<string, string[]>();

        if (userId != null)
        {
            claims["sub"] = [userId];
        }

        if (additionalClaims != null)
        {
            foreach (var claim in additionalClaims)
            {
                claims[claim.Key] = [claim.Value];
            }
        }

        return new AuthenticationContext
        {
            AccessToken = accessToken,
            RefreshToken = "test-refresh-token",
            IdToken = "test-id-token",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            Claims = claims
        };
    }

    /// <summary>
    /// Creates an unauthenticated AuthenticationContext.
    /// </summary>
    public static AuthenticationContext CreateUnauthenticatedContext()
    {
        return new AuthenticationContext
        {
            AccessToken = null,
            RefreshToken = null,
            IdToken = null,
            ExpiresAt = null,
            Claims = []
        };
    }

    /// <summary>
    /// Creates an expired AuthenticationContext.
    /// </summary>
    public static AuthenticationContext CreateExpiredAuthContext(string userId = "12345")
    {
        return new AuthenticationContext
        {
            AccessToken = "expired-token",
            RefreshToken = "test-refresh-token",
            IdToken = "test-id-token",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-5), // Expired 5 minutes ago
            Claims = new Dictionary<string, string[]>
            {
                ["sub"] = [userId]
            }
        };
    }

    /// <summary>
    /// Creates a TransformerContext with the specified parameters.
    /// </summary>
    public static TransformerContext CreateTransformerContext(
        AuthenticationContext? authContext = null,
        IBackendCaller? backendCaller = null,
        HttpContext? httpContext = null,
        Dictionary<string, object?>? routeValues = null,
        Dictionary<string, StringValues>? queryParameters = null,
        Dictionary<string, StringValues>? requestHeaders = null,
        Dictionary<string, object>? properties = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        var context = new TransformerContext
        {
            AuthContext = authContext ?? CreateAuthContext(),
            BackendCaller = backendCaller ?? new MockBackendCaller(),
            HttpContext = httpContext ?? CreateHttpContext(),
            RouteValues = routeValues ?? new Dictionary<string, object?>(),
            QueryParameters = queryParameters ?? new Dictionary<string, StringValues>(),
            RequestHeaders = requestHeaders ?? new Dictionary<string, StringValues>(),
            Properties = properties ?? new Dictionary<string, object>(),
            Logger = logger ?? NullLogger.Instance,
            CancellationToken = cancellationToken
        };

        return context;
    }

    /// <summary>
    /// Creates a TransformerContext with a backend request configured.
    /// </summary>
    public static TransformerContext CreateTransformerContextWithBackendRequest(
        BackendRequest backendRequest,
        AuthenticationContext? authContext = null,
        IBackendCaller? backendCaller = null,
        HttpContext? httpContext = null,
        Dictionary<string, object?>? routeValues = null,
        Dictionary<string, StringValues>? queryParameters = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        var properties = new Dictionary<string, object>
        {
            ["BackendRequest"] = backendRequest
        };

        return CreateTransformerContext(
            authContext: authContext,
            backendCaller: backendCaller,
            httpContext: httpContext,
            routeValues: routeValues,
            queryParameters: queryParameters,
            properties: properties,
            logger: logger,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Creates a TransformerContext with named backends configured.
    /// </summary>
    public static TransformerContext CreateTransformerContextWithNamedBackends(
        NamedBackendEndpoints namedBackends,
        AuthenticationContext? authContext = null,
        IBackendCaller? backendCaller = null,
        HttpContext? httpContext = null,
        Dictionary<string, object?>? routeValues = null,
        Dictionary<string, StringValues>? queryParameters = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        var properties = new Dictionary<string, object>
        {
            ["NamedBackends"] = namedBackends
        };

        return CreateTransformerContext(
            authContext: authContext,
            backendCaller: backendCaller,
            httpContext: httpContext,
            routeValues: routeValues,
            queryParameters: queryParameters,
            properties: properties,
            logger: logger,
            cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Creates a basic HttpContext for testing.
    /// </summary>
    public static HttpContext CreateHttpContext(
        string method = "GET",
        string path = "/test",
        Dictionary<string, string>? headers = null,
        Dictionary<string, string>? queryString = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;

        if (headers != null)
        {
            foreach (var header in headers)
            {
                context.Request.Headers[header.Key] = header.Value;
            }
        }

        if (queryString != null && queryString.Count > 0)
        {
            var qs = string.Join("&", queryString.Select(kv => $"{kv.Key}={Uri.EscapeDataString(kv.Value)}"));
            context.Request.QueryString = new QueryString($"?{qs}");
        }

        // Set up response body stream to capture written content
        context.Response.Body = new MemoryStream();

        return context;
    }

    /// <summary>
    /// Creates a default BackendRequest for testing.
    /// </summary>
    public static BackendRequest CreateBackendRequest(
        string method = "POST",
        string url = "http://backend-service/api/test",
        string? backendAuthPolicy = BackendAuthPolicies.BasicAuth,
        string? accessToken = null,
        TimeSpan? timeout = null)
    {
        return new BackendRequest
        {
            Method = method,
            Url = url,
            BackendAuthPolicy = backendAuthPolicy,
            AccessToken = accessToken,
            Timeout = timeout
        };
    }

    /// <summary>
    /// Creates NamedBackendEndpoints for multi-backend testing.
    /// </summary>
    public static NamedBackendEndpoints CreateNamedBackends(params (string Name, string Method, string Url, string? AuthPolicy)[] endpoints)
    {
        var namedBackends = new NamedBackendEndpoints();
        foreach (var (name, method, url, authPolicy) in endpoints)
        {
            namedBackends.Add(new NamedBackendEndpoint
            {
                Name = name,
                Method = method,
                UrlTemplate = url,
                BackendAuthPolicy = authPolicy
            });
        }
        return namedBackends;
    }

    /// <summary>
    /// Gets the response body as a string from an HttpContext.
    /// </summary>
    public static async Task<string> GetResponseBodyAsync(HttpContext context)
    {
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body);
        return await reader.ReadToEndAsync();
    }
}
