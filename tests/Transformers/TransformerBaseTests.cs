using System.Net.Http.Json;
using System.Text.Json;

using b17s.Porta.Tests.Fixtures;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Direct unit tests for <see cref="TransformerBase{TRequest, TResponse}"/> and
/// <see cref="TransformerBase{TResponse}"/>. The helper methods are protected, so
/// each test uses a small private subclass that exposes the surface under test.
/// </summary>
public sealed class TransformerBaseTests
{
    [Fact]
    public async Task CallBackendAsync_NoBackendRequestInContext_ReturnsConfigurationError()
    {
        // The TransformerEndpointBuilder normally seeds Properties["BackendRequest"].
        // When absent (misuse, custom call site) the helper should return a structured
        // failure instead of throwing - callers can then WriteBackendErrorResponseAsync.
        var sut = new ExposedTransformer<string, string>();
        var context = TestFixtures.CreateTransformerContext(cancellationToken: TestContext.Current.CancellationToken);

        var result = await sut.CallBackendForTestAsync("body", context);

        Assert.False(result.IsSuccess);
        Assert.Equal(500, result.StatusCode);
        Assert.Contains("Backend request configuration", result.Error);
    }

    [Fact]
    public async Task CallBackendAsync_WithBody_ForwardsRequestAndBodyToBackendCaller()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://backend/api", new EchoResponse { Value = "ok" });
        var request = TestFixtures.CreateBackendRequest(method: "POST", url: "http://backend/api");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoRequest, EchoResponse>();

        var payload = new EchoRequest { Name = "x" };
        var result = await sut.CallBackendForTestAsync(payload, context);

        Assert.True(result.IsSuccess);
        Assert.Equal("ok", result.Value!.Value);
        Assert.Single(backend.RecordedCalls);
        Assert.Same(payload, backend.LastCall!.GetBody<EchoRequest>());
    }

    [Fact]
    public async Task CallBackendAsync_NullBody_UsesParameterlessCallAsync()
    {
        // request == null on the two-arg overload should hit CallAsync<TResponse>(req, ct),
        // not the body-bearing overload (would NPE with null body in real callers).
        var backend = new MockBackendCaller()
            .SetupResponse("http://backend/api", new EchoResponse { Value = "got" });
        var request = TestFixtures.CreateBackendRequest(method: "GET", url: "http://backend/api");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoRequest, EchoResponse>();

        var result = await sut.CallBackendForTestAsync(null, context);

        Assert.True(result.IsSuccess);
        Assert.Null(backend.LastCall!.Body);
    }

    [Fact]
    public async Task CallBackendAsync_WithBackendUrlOverride_RewritesUrl()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://override/api", new EchoResponse { Value = "override" });
        var request = TestFixtures.CreateBackendRequest(url: "http://backend/api");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<EchoRequest, EchoResponse>();

        var result = await sut.CallBackendForTestAsync(null, context, "http://override/api");

        Assert.True(result.IsSuccess);
        Assert.Equal("http://override/api", backend.LastCall!.Request.Url);
    }

    [Fact]
    public void GetClaim_ReturnsValueWhenPresent_NullWhenAbsent()
    {
        var auth = TestFixtures.CreateAuthContext(additionalClaims: new() { ["email"] = "ada@example.com" });
        var context = TestFixtures.CreateTransformerContext(authContext: auth, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>();

        Assert.Equal("ada@example.com", sut.GetClaimForTest(context, "email"));
        Assert.Null(sut.GetClaimForTest(context, "department"));
    }

    [Fact]
    public void GetRequiredClaim_ReturnsNullForMissingClaim()
    {
        // GetRequiredClaim logs the miss via the source-generated logger; the logger field
        // is normally seeded by InitializeLogger inside Transform/CallBackendAsync. When
        // tests exercise the helper standalone, prime it through the public surface.
        var auth = TestFixtures.CreateAuthContext();
        var context = TestFixtures.CreateTransformerContext(authContext: auth, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>();
        sut.PrimeLogger(context);

        Assert.Null(sut.GetRequiredClaimForTest(context, "tenant_id"));
    }

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
        var sut = new ExposedTransformer<object, object>();

        Assert.Equal("42", sut.GetRouteValueForTest(context, "id"));
        Assert.Null(sut.GetRouteValueForTest(context, "missing"));
        Assert.Equal("one", sut.GetQueryParameterForTest(context, "single"));
        // Singular getter returns the FIRST value, not a comma-joined string.
        Assert.Equal("a", sut.GetQueryParameterForTest(context, "tag"));
        Assert.Equal(["a", "b", "c"], sut.GetQueryValuesForTest(context, "tag").ToArray());
        Assert.Empty(sut.GetQueryValuesForTest(context, "missing"));
    }

    [Fact]
    public void RequestHeaders_ReadAndResponseHeadersWrite()
    {
        var requestHeaders = new Dictionary<string, StringValues>
        {
            ["X-Custom"] = new(["first", "second"]),
        };
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, requestHeaders: requestHeaders, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>();

        // Singular getter returns the FIRST value, not a comma-joined string.
        Assert.Equal("first", sut.GetRequestHeaderForTest(context, "X-Custom"));
        Assert.Equal(["first", "second"], sut.GetRequestHeadersForTest(context, "X-Custom").ToArray());
        Assert.Null(sut.GetRequestHeaderForTest(context, "missing"));

        sut.SetResponseHeaderForTest(context, "X-Out", "value");
        Assert.Equal("value", http.Response.Headers["X-Out"]);

        sut.AddResponseHeaderForTest(context, "X-Out", "second");
        Assert.Equal(["value", "second"], http.Response.Headers["X-Out"].Select(v => v!).ToArray());

        sut.RemoveResponseHeaderForTest(context, "X-Out");
        Assert.False(http.Response.Headers.ContainsKey("X-Out"));
    }

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(500)]
    public async Task WriteErrorResponseAsync_WritesAuthorStatusVerbatim(int status)
    {
        // The general-purpose writer passes the author's status through unchanged - including a
        // genuine user-facing 401/403. The backend 401/403 -> 502 remap lives only in
        // WriteBackendErrorResponseAsync now.
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>();

        await sut.WriteErrorResponseForTestAsync(context, status, "original");

        Assert.Equal(status, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        var json = JsonDocument.Parse(body);
        Assert.Equal("original", json.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task WriteBackendErrorResponseAsync_UsesResultStatusAndErrorMessage()
    {
        // A non-401/403, non-5xx backend status (e.g. 429) relays its status and message as-is.
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>();

        var failure = BackendResult<string>.Failure(429, "Too many requests", BackendErrorType.Unknown);
        await sut.WriteBackendErrorResponseForTestAsync(context, failure);

        Assert.Equal(429, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.Contains("Too many requests", body);
    }

    [Theory]
    [InlineData(401, "Backend service authentication failed")]
    [InlineData(403, "Backend service authorization failed")]
    public async Task WriteBackendErrorResponseAsync_RemapsBackend401And403To502_AndHidesDetail(int backendStatus, string expectedMessage)
    {
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>();

        var failure = BackendResult<string>.Failure(backendStatus, "raw backend detail", BackendErrorType.AuthenticationError);
        await sut.WriteBackendErrorResponseForTestAsync(context, failure);

        Assert.Equal(502, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.Contains(expectedMessage, body);
        Assert.DoesNotContain("raw backend detail", body);
    }

    [Fact]
    public async Task WriteBackendErrorResponseAsync_Backend5xx_MasksRawDetailFromClient()
    {
        // Backend 5xx error text (which can echo deserializer output / reason phrases) must not
        // reach the client - the body carries a generic message instead.
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>();

        var failure = BackendResult<string>.Failure(500, "Invalid response format: secret detail", BackendErrorType.ServerError);
        await sut.WriteBackendErrorResponseForTestAsync(context, failure);

        Assert.Equal(500, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.DoesNotContain("secret detail", body);
        Assert.Contains("Backend service error", body);
    }

    [Theory]
    [InlineData("UNAUTHENTICATED", 401)]
    [InlineData("UNAUTHORIZED", 401)]
    [InlineData("FORBIDDEN", 403)]
    [InlineData("ACCESS_DENIED", 403)]
    public async Task WriteGraphQLErrorResponseAsync_ApplicationAuthError_SurfacesDocumented401Or403(string code, int expectedStatus)
    {
        // Regression: an application-level GraphQL auth error (HTTP 200 + UNAUTHENTICATED/FORBIDDEN)
        // must reach the client as the documented 401/403 - NOT the 502 that
        // WriteBackendErrorResponseAsync(result.ToBackendResult()) would have produced.
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>();

        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "not authorized", Extensions = new GraphQLErrorExtensions { Code = code } },
        });
        await sut.WriteGraphQLErrorResponseForTestAsync(context, result);

        Assert.Equal(expectedStatus, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.Contains("not authorized", body);
    }

    [Fact]
    public async Task WriteGraphQLErrorResponseAsync_RelaysMappedClientStatusAndMessageVerbatim()
    {
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>();

        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "Product not found", Extensions = new GraphQLErrorExtensions { Code = "NOT_FOUND" } },
        });
        await sut.WriteGraphQLErrorResponseForTestAsync(context, result);

        Assert.Equal(404, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.Contains("Product not found", body);
    }

    [Fact]
    public async Task WriteGraphQLErrorResponseAsync_Mapped5xx_MasksDetailFromClient()
    {
        // 5xx detail (e.g. an INTERNAL_SERVER_ERROR message) is masked, matching the backend writer.
        var http = TestFixtures.CreateHttpContext();
        var context = TestFixtures.CreateTransformerContext(httpContext: http, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>();

        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "stack trace: secret detail", Extensions = new GraphQLErrorExtensions { Code = "INTERNAL_SERVER_ERROR" } },
        });
        await sut.WriteGraphQLErrorResponseForTestAsync(context, result);

        Assert.Equal(500, http.Response.StatusCode);
        var body = await TestFixtures.GetResponseBodyAsync(http);
        Assert.DoesNotContain("secret detail", body);
        Assert.Contains("Backend service error", body);
    }

    [Fact]
    public void GetRequiredClaim_BeforeLoggerInit_DoesNotThrow()
    {
        // Logger defaults to NullLogger, so a transformer that calls a logging helper before the
        // framework runs InitializeLogger no longer dereferences a null logger.
        var context = TestFixtures.CreateTransformerContext(
            authContext: TestFixtures.CreateAuthContext(), cancellationToken: TestContext.Current.CancellationToken);
        var sut = new ExposedTransformer<object, object>(); // intentionally NOT primed

        Assert.Null(sut.GetRequiredClaimForTest(context, "missing"));
    }

    [Fact]
    public async Task PassThroughTransformer_AnonymousAllowed_ReturnsBackendValue()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://backend/data", new EchoResponse { Value = "anon-ok" });
        var request = TestFixtures.CreateBackendRequest(url: "http://backend/data");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(
            request,
            authContext: TestFixtures.CreateUnauthenticatedContext(),
            backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new TestPassThrough { Required = false };

        var result = await sut.TransformAsync(context);

        Assert.Equal("anon-ok", result.Value);
    }

    [Fact]
    public async Task PassThroughTransformer_RequiresAuth_NoSubClaim_Returns401_NoBackendCall()
    {
        // RequiresAuthentication=true short-circuits before any backend call when the user
        // has no sub claim. The client must see 401 (its own auth failed), not the 502 that
        // WriteErrorResponseAsync would emit for backend auth failures.
        var backend = new MockBackendCaller();
        var request = TestFixtures.CreateBackendRequest(url: "http://backend/data");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(
            request,
            authContext: TestFixtures.CreateAuthContext(userId: null),
            backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new TestPassThrough { Required = true };

        var result = await sut.TransformAsync(context);

        Assert.Null(result);
        Assert.Equal(401, context.HttpContext.Response.StatusCode);
        Assert.Empty(backend.RecordedCalls);

        var body = await TestFixtures.GetResponseBodyAsync(context.HttpContext);
        var json = JsonDocument.Parse(body);
        Assert.Equal("User not authenticated", json.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task PassThroughTransformer_BackendFailure_WritesMappedErrorAndReturnsDefault()
    {
        // A 401 from the backend means BFF-to-backend creds are wrong - re-emit as 502.
        var backend = new MockBackendCaller()
            .SetupAuthenticationFailure<EchoResponse>("http://backend/data");
        var request = TestFixtures.CreateBackendRequest(url: "http://backend/data");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new TestPassThrough { Required = false };

        var result = await sut.TransformAsync(context);

        Assert.Null(result);
        Assert.Equal(502, context.HttpContext.Response.StatusCode);
    }

    [Fact]
    public async Task PassThroughTransformer_TransformResponseHook_MutatesValue()
    {
        // TransformResponse is the override point - verify it runs on the success path.
        var backend = new MockBackendCaller()
            .SetupResponse("http://backend/data", new EchoResponse { Value = "raw" });
        var request = TestFixtures.CreateBackendRequest(url: "http://backend/data");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new TransformingPassThrough();

        var result = await sut.TransformAsync(context);

        Assert.Equal("RAW-transformed", result.Value);
    }

    [Fact]
    public async Task AuthenticatedTransformer_Unauthenticated_Returns401_NoBackendCall()
    {
        var backend = new MockBackendCaller();
        var request = TestFixtures.CreateBackendRequest(url: "http://backend/data");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(
            request,
            authContext: TestFixtures.CreateAuthContext(userId: null),
            backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new TestAuthenticatedWithBody();

        var result = await sut.TransformAsync(context);

        Assert.Null(result);
        Assert.Equal(401, context.HttpContext.Response.StatusCode);
        Assert.Empty(backend.RecordedCalls);
    }

    [Fact]
    public async Task AuthenticatedTransformer_Authenticated_SendsCreatedBackendRequest()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://backend/data", new EchoResponse { Value = "hi" });
        var request = TestFixtures.CreateBackendRequest(url: "http://backend/data");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(
            request,
            authContext: TestFixtures.CreateAuthContext(userId: "user-7"),
            backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new TestAuthenticatedWithBody();

        var result = await sut.TransformAsync(context);

        Assert.Equal("hi", result.Value);
        Assert.Equal("user-7", backend.LastCall!.GetBody<EchoRequest>()!.Name);
    }

    [Fact]
    public async Task BackendForwardingTransformer_Success_ReturnsValue()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("http://backend/data", new EchoResponse { Value = "fwd" });
        var request = TestFixtures.CreateBackendRequest(url: "http://backend/data");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new BackendForwardingTransformer<EchoResponse>();

        var result = await sut.TransformAsync(context);

        Assert.Equal("fwd", result.Value);
    }

    [Fact]
    public async Task BackendForwardingTransformer_Failure_WritesStatusVerbatim()
    {
        // BackendForwardingTransformer trusts the BackendResult's StatusCode (already mapped
        // upstream by IBackendErrorMapper) and writes the JSON error envelope directly,
        // setting HasStarted so the outer handler does not double-write.
        var backend = new MockBackendCaller()
            .SetupFailure<EchoResponse>("http://backend/data", 503, "Service Unavailable");
        var request = TestFixtures.CreateBackendRequest(url: "http://backend/data");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new BackendForwardingTransformer<EchoResponse>();

        var result = await sut.TransformAsync(context);

        Assert.Null(result);
        Assert.Equal(503, context.HttpContext.Response.StatusCode);
        Assert.True(context.HttpContext.Response.HasStarted || context.HttpContext.Response.Body.Length > 0);
        var body = await TestFixtures.GetResponseBodyAsync(context.HttpContext);
        var json = JsonDocument.Parse(body);
        Assert.Equal("Service Unavailable", json.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task BackendForwardingTransformer_FailureWithNullError_UsesFallbackMessage()
    {
        var backend = new MockBackendCaller()
            .SetupFailure<EchoResponse>("http://backend/data", 500, null!);
        var request = TestFixtures.CreateBackendRequest(url: "http://backend/data");
        var context = TestFixtures.CreateTransformerContextWithBackendRequest(request, backendCaller: backend, cancellationToken: TestContext.Current.CancellationToken);
        var sut = new BackendForwardingTransformer<EchoResponse>();

        await sut.TransformAsync(context);

        var body = await TestFixtures.GetResponseBodyAsync(context.HttpContext);
        var json = JsonDocument.Parse(body);
        Assert.Equal("Backend request failed", json.RootElement.GetProperty("error").GetString());
    }

    public sealed class EchoRequest
    {
        public string Name { get; set; } = string.Empty;
        public int Count { get; set; }
    }

    public sealed class EchoResponse
    {
        public string Value { get; set; } = string.Empty;
    }

    /// <summary>Test-only subclass that exposes the protected helpers on TransformerBase.</summary>
    private sealed class ExposedTransformer<TRequest, TResponse> : TransformerBase<TRequest, TResponse>
    {
        public override Task<TResponse> TransformAsync(TRequest? request, TransformerContext context)
            => Task.FromResult(default(TResponse)!);

        public Task<BackendResult<TResponse>> CallBackendForTestAsync(TRequest? request, TransformerContext context)
            => CallBackendAsync(request, context);

        public Task<BackendResult<TResponse>> CallBackendForTestAsync(TRequest? request, TransformerContext context, string url)
            => CallBackendAsync(request, context, url);

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

    private sealed class TestPassThrough : PassThroughTransformer<EchoResponse>
    {
        public bool Required { get; init; }
        protected override bool RequiresAuthentication => Required;
    }

    private sealed class TransformingPassThrough : PassThroughTransformer<EchoResponse>
    {
        protected override EchoResponse TransformResponse(EchoResponse response, TransformerContext context)
            => new() { Value = response.Value.ToUpperInvariant() + "-transformed" };
    }

    private sealed class TestAuthenticatedWithBody : AuthenticatedTransformer<EchoRequest, EchoResponse>
    {
        protected override EchoRequest CreateBackendRequest(TransformerContext context)
            => new() { Name = context.UserId! };
    }
}
