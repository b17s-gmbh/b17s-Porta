using System.Text.Json;

using b17s.Porta.Tests.Fixtures;
using b17s.Porta.Transformers;

using Microsoft.Extensions.Primitives;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Tests for <see cref="TransformerBase{TResponse}"/> — the no-body twin of the
/// body-bearing class already covered by <see cref="TransformerBaseTests"/>. The two
/// classes share helper shapes but have entirely separate IL bodies, so the coverage
/// report flagged these as unreached. These tests mirror the body-bearing assertions
/// against the no-body class through an exposing subclass.
/// </summary>
public sealed class TransformerBaseNoBodyTests
{
    [Fact]
    public async Task CallBackendAsync_NoBackendRequestInContext_ReturnsConfigurationError()
    {
        var sut = new ExposedTransformer<string>();
        var context = TestFixtures.CreateTransformerContext(cancellationToken: TestContext.Current.CancellationToken);

        var result = await sut.CallBackendForTestAsync(context);

        Assert.False(result.IsSuccess);
        Assert.Equal(500, result.StatusCode);
        Assert.Contains("Backend request configuration", result.Error);
    }

    [Fact]
    public async Task CallBackendAsync_DispatchesToParameterlessOverload()
    {
        // The no-body class only has CallAsync<TResponse>(req, ct) - body forwarding
        // isn't part of its surface. Confirm the request reaches the mock and no body
        // is attached.
        var backend = new MockBackendCaller()
            .SetupResponse("http://backend/api", new EchoResponse { Value = "ok" });
        var request = TestFixtures.CreateBackendRequest(method: "GET", url: "http://backend/api");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        var result = await sut.CallBackendForTestAsync(context);

        Assert.True(result.IsSuccess);
        Assert.Equal("ok", result.Value!.Value);
        Assert.Null(backend.LastCall!.Body);
    }

    [Fact]
    public async Task CallBackendAsync_WithUrlOverride_RewritesUrl()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://override/api", new EchoResponse { Value = "over" });
        var request = TestFixtures.CreateBackendRequest(url: "http://original/api");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        var result = await sut.CallBackendForTestAsync(context, "http://override/api");

        Assert.True(result.IsSuccess);
        Assert.Equal("http://override/api", backend.LastCall!.Request.Url);
    }

    [Fact]
    public async Task CallBackendAsync_UrlOverride_NoBackendRequest_ReturnsConfigError()
    {
        var sut = new ExposedTransformer<EchoResponse>();
        var context = TestFixtures.CreateTransformerContext(cancellationToken: TestContext.Current.CancellationToken);

        var result = await sut.CallBackendForTestAsync(context, "http://other/api");

        Assert.False(result.IsSuccess);
        Assert.Equal(500, result.StatusCode);
    }

    [Fact]
    public async Task CallBackendAsync_WithModifiedRequest_SendsModifiedBody()
    {
        // The generic CallBackendAsync<TModifiedRequest>(body, context) overload
        // routes through CallAsync<TRequest, TResponse> on the caller.
        var backend = new MockBackendCaller()
            .SetupResponse("http://backend/api", new EchoResponse { Value = "ok" });
        var request = TestFixtures.CreateBackendRequest(method: "POST", url: "http://backend/api");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        var body = new ModifiedRequest { Field = "value" };
        var result = await sut.CallBackendWithModifiedForTestAsync(body, context);

        Assert.True(result.IsSuccess);
        Assert.Same(body, backend.LastCall!.GetBody<ModifiedRequest>());
    }

    [Fact]
    public async Task CallBackendAsync_WithModifiedRequest_NoBackendRequest_ReturnsConfigError()
    {
        var sut = new ExposedTransformer<EchoResponse>();
        var context = TestFixtures.CreateTransformerContext(cancellationToken: TestContext.Current.CancellationToken);

        var result = await sut.CallBackendWithModifiedForTestAsync(new ModifiedRequest(), context);

        Assert.False(result.IsSuccess);
        Assert.Equal(500, result.StatusCode);
    }

    // -----------------------------
    // Claim helpers
    // -----------------------------

    [Fact]
    public void GetClaim_ReturnsValueOrNull()
    {
        var auth = TestFixtures.CreateAuthContext(additionalClaims: new() { ["email"] = "ada@example.com" });
        var context = TestFixtures.CreateTransformerContext(authContext: auth, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        Assert.Equal("ada@example.com", sut.GetClaimForTest(context, "email"));
        Assert.Null(sut.GetClaimForTest(context, "department"));
    }

    [Fact]
    public void GetRequiredClaim_ReturnsNullForMissingClaim()
    {
        var auth = TestFixtures.CreateAuthContext();
        var context = TestFixtures.CreateTransformerContext(authContext: auth, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();
        sut.PrimeLogger(context);

        Assert.Null(sut.GetRequiredClaimForTest(context, "tenant_id"));
    }

    [Fact]
    public void GetRequiredClaim_ReturnsValueWhenPresent()
    {
        var auth = TestFixtures.CreateAuthContext(additionalClaims: new() { ["tenant_id"] = "tenant-7" });
        var context = TestFixtures.CreateTransformerContext(authContext: auth, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();
        sut.PrimeLogger(context);

        Assert.Equal("tenant-7", sut.GetRequiredClaimForTest(context, "tenant_id"));
    }

    // -----------------------------
    // Route, query, header helpers
    // -----------------------------

    [Fact]
    public void GetRouteAndQueryValues_ReadFromContext()
    {
        var query = new Dictionary<string, StringValues>
        {
            ["tag"] = new(["a", "b", "c"]),
            ["single"] = "one",
        };
        var route = new Dictionary<string, object?> { ["id"] = 42 };
        var context = TestFixtures.CreateTransformerContext(routeValues: route, queryParameters: query, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        Assert.Equal("42", sut.GetRouteValueForTest(context, "id"));
        Assert.Null(sut.GetRouteValueForTest(context, "missing"));
        Assert.Equal("one", sut.GetQueryParameterForTest(context, "single"));
        Assert.Null(sut.GetQueryParameterForTest(context, "missing"));
        // Singular getter returns the FIRST value, not a comma-joined string.
        Assert.Equal("a", sut.GetQueryParameterForTest(context, "tag"));
        Assert.Equal(new[] { "a", "b", "c" }, sut.GetQueryValuesForTest(context, "tag").ToArray());
        Assert.Empty(sut.GetQueryValuesForTest(context, "missing"));
    }

    [Fact]
    public void RequestHeaders_ReadAndResponseHeaders_Write()
    {
        var requestHeaders = new Dictionary<string, StringValues>
        {
            ["X-Custom"] = new(["first", "second"]),
        };
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, requestHeaders: requestHeaders, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        // Singular getter returns the FIRST value, not a comma-joined string.
        Assert.Equal("first", sut.GetRequestHeaderForTest(context, "X-Custom"));
        Assert.Equal(new[] { "first", "second" }, sut.GetRequestHeadersForTest(context, "X-Custom").ToArray());
        Assert.Null(sut.GetRequestHeaderForTest(context, "missing"));
        Assert.Empty(sut.GetRequestHeadersForTest(context, "missing"));

        sut.SetResponseHeaderForTest(context, "X-Out", "value");
        Assert.Equal("value", http.Response.Headers["X-Out"]);

        sut.AddResponseHeaderForTest(context, "X-Out", "second");
        Assert.Equal(new[] { "value", "second" }, http.Response.Headers["X-Out"].ToArray()!);

        sut.RemoveResponseHeaderForTest(context, "X-Out");
        Assert.False(http.Response.Headers.ContainsKey("X-Out"));
    }

    // -----------------------------
    // Error-response writers — author status verbatim vs backend-status remap
    // -----------------------------

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(500)]
    public async Task WriteErrorResponseAsync_WritesAuthorStatusVerbatim(int status)
    {
        // The general-purpose writer passes the author's status through unchanged - including a
        // genuine user-facing 401/403. The backend remap lives in WriteBackendErrorResponseAsync.
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        await sut.WriteErrorResponseForTestAsync(context, status, "original");

        Assert.Equal(status, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        var json = JsonDocument.Parse(body);
        Assert.Equal("original", json.RootElement.GetProperty("error").GetString());
    }

    [Theory]
    [InlineData(401, "Backend service authentication failed")]
    [InlineData(403, "Backend service authorization failed")]
    public async Task WriteBackendErrorResponseAsync_RemapsBackend401And403To502_AndHidesDetail(int backendStatus, string expectedMessage)
    {
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        var failure = BackendResult<EchoResponse>.Failure(backendStatus, "raw backend detail");
        await sut.WriteBackendErrorResponseForTestAsync(context, failure);

        Assert.Equal(502, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.Contains(expectedMessage, body);
        Assert.DoesNotContain("raw backend detail", body);
    }

    [Fact]
    public async Task WriteBackendErrorResponseAsync_UsesResultStatusAndMessage()
    {
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        var failure = BackendResult<EchoResponse>.Failure(429, "Too many requests");
        await sut.WriteBackendErrorResponseForTestAsync(context, failure);

        Assert.Equal(429, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.Contains("Too many requests", body);
    }

    [Fact]
    public async Task WriteBackendErrorResponseAsync_Backend5xx_MasksRawDetailFromClient()
    {
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        var failure = BackendResult<EchoResponse>.Failure(500, "Invalid response format: secret detail");
        await sut.WriteBackendErrorResponseForTestAsync(context, failure);

        Assert.Equal(500, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.DoesNotContain("secret detail", body);
        Assert.Contains("Backend service error", body);
    }

    [Fact]
    public async Task WriteBackendErrorResponseAsync_NullError_UsesFallbackMessage()
    {
        // Null Error on a relayed (non-5xx) status falls back to the generic "Backend request failed".
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        var failure = BackendResult<EchoResponse>.Failure(404, null!);
        await sut.WriteBackendErrorResponseForTestAsync(context, failure);

        var body = await TestFixtures.GetResponseBodyAsync(http);
        var json = JsonDocument.Parse(body);
        Assert.Equal("Backend request failed", json.RootElement.GetProperty("error").GetString());
    }

    [Theory]
    [InlineData("UNAUTHENTICATED", 401)]
    [InlineData("FORBIDDEN", 403)]
    public async Task WriteGraphQLErrorResponseAsync_ApplicationAuthError_SurfacesDocumented401Or403(string code, int expectedStatus)
    {
        // Mirrors the body-bearing class: GraphQL application auth errors surface as 401/403, not 502.
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "denied", Extensions = new GraphQLErrorExtensions { Code = code } },
        });
        await sut.WriteGraphQLErrorResponseForTestAsync(context, result);

        Assert.Equal(expectedStatus, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.Contains("denied", body);
    }

    [Fact]
    public async Task WriteGraphQLErrorResponseAsync_Mapped5xx_MasksDetailFromClient()
    {
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoResponse>();

        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "secret detail", Extensions = new GraphQLErrorExtensions { Code = "INTERNAL_SERVER_ERROR" } },
        });
        await sut.WriteGraphQLErrorResponseForTestAsync(context, result);

        Assert.Equal(500, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.DoesNotContain("secret detail", body);
        Assert.Contains("Backend service error", body);
    }

    // -----------------------------
    // Test doubles
    // -----------------------------

    public sealed class EchoResponse
    {
        public string Value { get; set; } = string.Empty;
    }

    public sealed class ModifiedRequest
    {
        public string Field { get; set; } = string.Empty;
    }

    /// <summary>Exposes the protected helpers on <see cref="TransformerBase{TResponse}"/>.</summary>
    private sealed class ExposedTransformer<TResponse> : TransformerBase<TResponse>
    {
        public override Task<TResponse> TransformAsync(TransformerContext context)
            => Task.FromResult(default(TResponse)!);

        public Task<BackendResult<TResponse>> CallBackendForTestAsync(TransformerContext context)
            => CallBackendAsync(context);

        public Task<BackendResult<TResponse>> CallBackendForTestAsync(TransformerContext context, string url)
            => CallBackendAsync(context, url);

        public Task<BackendResult<TResponse>> CallBackendWithModifiedForTestAsync<TModified>(TModified modified, TransformerContext context)
            => CallBackendAsync(modified, context);

        public void PrimeLogger(TransformerContext context) => InitializeLogger(context);

        public string? GetClaimForTest(TransformerContext context, string claim) => GetClaim(context, claim);
        public string? GetRequiredClaimForTest(TransformerContext context, string claim) => GetRequiredClaim(context, claim);
        public string? GetRouteValueForTest(TransformerContext context, string key) => GetRouteValue(context, key);
        public string? GetQueryParameterForTest(TransformerContext context, string key) => GetQueryParameter(context, key);
        public IEnumerable<string> GetQueryValuesForTest(TransformerContext context, string key) => GetQueryValues(context, key);
        public string? GetRequestHeaderForTest(TransformerContext context, string name) => GetRequestHeader(context, name);
        public IEnumerable<string> GetRequestHeadersForTest(TransformerContext context, string name) => GetRequestHeaders(context, name);
        public void SetResponseHeaderForTest(TransformerContext context, string name, string value) => SetResponseHeader(context, name, value);
        public void AddResponseHeaderForTest(TransformerContext context, string name, string value) => AddResponseHeader(context, name, value);
        public void RemoveResponseHeaderForTest(TransformerContext context, string name) => RemoveResponseHeader(context, name);

        public Task WriteErrorResponseForTestAsync(TransformerContext context, int status, string err)
            => WriteErrorResponseAsync(context, status, err);

        public Task WriteBackendErrorResponseForTestAsync<T>(TransformerContext context, BackendResult<T> result)
            => WriteBackendErrorResponseAsync(context, result);

        public Task WriteGraphQLErrorResponseForTestAsync<TData>(TransformerContext context, GraphQLResult<TData> result)
            => WriteGraphQLErrorResponseAsync(context, result);
    }
}
