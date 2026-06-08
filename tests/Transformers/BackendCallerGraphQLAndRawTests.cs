using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Tests for the previously-unreached GraphQL and raw paths through <see cref="BackendCaller"/>:
/// <see cref="BackendCaller.CallGraphQLAsync{TResponse}"/>, <see cref="BackendCaller.CallRawAsync(BackendRequest, CancellationToken)"/>,
/// the body-stream raw variant, the bounded response reader (DoS guard), and the failure paths in
/// <c>SendRawRequestAsync</c> (timeout, network failure, auth-handler failure, generic).
/// </summary>
[Collection(PortaActivitySourceCollection.Name)]
public sealed class BackendCallerGraphQLAndRawTests
{
    // ===========================================================================
    // CallGraphQLAsync — request shape
    // ===========================================================================

    [Fact]
    public async Task GraphQL_HappyPath_SerializesQueryAndExtractsDataPath()
    {
        var handler = new StubHandler(
            HttpStatusCode.OK,
            """{"data":{"product":{"id":"abc","name":"Widget"}}}""",
            "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request,
            "query GetProduct($id: ID!) { product(id: $id) { id name } }",
            new { id = "abc" },
            dataPath: "product",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Data);
        Assert.Equal("abc", result.Data!.Id);
        Assert.Equal("Widget", result.Data.Name);

        // Outbound request shape: POST + JSON envelope with query + variables.
        Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
        Assert.Equal("application/json", handler.LastRequest.Content?.Headers.ContentType?.MediaType);
        Assert.NotNull(handler.LastBody);
        Assert.Contains("\"query\":\"query GetProduct", handler.LastBody!);
        Assert.Contains("\"variables\":{\"id\":\"abc\"}", handler.LastBody);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task GraphQL_CoercesNonPostMethodsToPost(string requestMethod)
    {
        // GraphQL spec is POST + JSON; CallGraphQLAsync must override the caller's
        // BackendRequest.Method regardless of what they specified.
        var handler = new StubHandler(HttpStatusCode.OK, """{"data":{"x":1}}""", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = requestMethod, Url = "https://backend.test/graphql" };
        await caller.CallGraphQLAsync<int>(
            request,
            "{ x }",
            variables: null,
            dataPath: "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
    }

    [Fact]
    public async Task GraphQL_OperationNameIsPropagatedInRequestBody()
    {
        var handler = new StubHandler(HttpStatusCode.OK, """{"data":{"product":{"id":"1","name":"x"}}}""", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        await caller.CallGraphQLAsync<Product>(
            request,
            "query A { product { id name } } query B { product { id } }",
            variables: null,
            dataPath: "product",
            operationName: "A",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotNull(handler.LastBody);
        Assert.Contains("\"operationName\":\"A\"", handler.LastBody!);
    }

    // ===========================================================================
    // CallGraphQLAsync — response handling
    // ===========================================================================

    [Fact]
    public async Task GraphQL_ErrorsArrayInResponse_ProducesGraphQLErrorsResult()
    {
        // Backend returns {"errors":[...]} -> caller must surface them via FromGraphQLErrors,
        // not treat as a success or a bare backend error.
        var handler = new StubHandler(
            HttpStatusCode.OK,
            """{"errors":[{"message":"Field 'x' not found","extensions":{"code":"NOT_FOUND"}}]}""",
            "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ x }", null, "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Errors);
        Assert.Single(result.Errors!);
        Assert.Equal("Field 'x' not found", result.Errors![0].Message);
        Assert.Equal(404, result.MappedStatusCode); // NOT_FOUND -> 404 via GraphQLResult mapping
    }

    [Fact]
    public async Task GraphQL_DataMissingAndNoErrors_ReturnsSuccessWithDefault()
    {
        // Unusual but legal GraphQL shape: {} or {"data":null}. The caller treats it as
        // success(default!) so the consumer can distinguish "no errors" from "errored".
        var handler = new StubHandler(HttpStatusCode.OK, """{"data":null}""", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ x }", null, "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Null(result.Data);
    }

    [Fact]
    public async Task GraphQL_InvalidJsonBody_ReturnsInvalidResponseError()
    {
        var handler = new StubHandler(HttpStatusCode.OK, "not-a-json-document", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ x }", null, "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.InvalidResponse, result.ErrorType);
        Assert.Contains("Invalid GraphQL response format", result.Error);
    }

    [Fact]
    public async Task GraphQL_EmptyResponseBody_ReturnsInvalidResponseError()
    {
        var handler = new StubHandler(HttpStatusCode.OK, "", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ x }", null, "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.InvalidResponse, result.ErrorType);
        Assert.Equal("Empty response from GraphQL backend", result.Error);
    }

    [Fact]
    public async Task GraphQL_ResponseExceedsMaxBytesByContentLength_ReturnsInvalidResponseError()
    {
        // Content-Length advertises a body larger than the cap; the bounded reader must
        // bail before pulling the body, returning the "exceeds maximum allowed size" message.
        var handler = new StubHandler(HttpStatusCode.OK, new string('a', 64), "application/json")
        {
            OverrideContentLength = 100_000_000 // far above the 1024 cap we configure below
        };
        var caller = CreateCaller(handler, maxBackendResponseBytes: 1024);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ x }", null, "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.InvalidResponse, result.ErrorType);
        Assert.Equal("Backend response exceeds maximum allowed size", result.Error);
    }

    [Fact]
    public async Task GraphQL_ResponseExceedsMaxBytesDuringStream_ReturnsInvalidResponseError()
    {
        // Content-Length is absent; the reader must catch the overflow mid-stream by
        // reading at most maxBytes + 1 and rejecting when the count crosses the cap.
        var bigBody = new string('a', 10_000);
        var handler = new StubHandler(HttpStatusCode.OK, bigBody, "application/json")
        {
            OverrideContentLength = -1L // signals "do not write a Content-Length header"
        };
        var caller = CreateCaller(handler, maxBackendResponseBytes: 1024);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ x }", null, "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.InvalidResponse, result.ErrorType);
        Assert.Equal("Backend response exceeds maximum allowed size", result.Error);
    }

    [Fact]
    public async Task GraphQL_HttpErrorFromBackend_ReturnsFromBackendErrorMapped()
    {
        // A non-2xx HTTP status with a benign-looking GraphQL envelope ({"data":null}, no errors)
        // must NOT be reported as a successful empty-data response. With no GraphQL `errors` to
        // surface, the HTTP failure wins and is routed through the same IBackendErrorMapper the
        // typed CallAsync overloads use. A 502 maps to 502 (ServerError).
        var handler = new StubHandler(HttpStatusCode.BadGateway, """{"data":null}""", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ x }", null, "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(502, result.HttpStatusCode);
        Assert.Equal(BackendErrorType.ServerError, result.ErrorType);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task GraphQL_BackendAuthFailure_MappedTo502_LikeTypedRoutes(HttpStatusCode backendStatus)
    {
        // A backend 401/403 means the BFF's credentials to the backend are wrong, NOT that the
        // user's session is invalid. The default mapper turns these into 502 so the frontend
        // doesn't sign the user out — identical to the typed CallAsync path.
        var handler = new StubHandler(backendStatus, """{"data":null}""", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ x }", null, "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(502, result.HttpStatusCode);
        Assert.Equal(BackendErrorType.ServerError, result.ErrorType);
    }

    [Fact]
    public async Task GraphQL_HttpErrorWithGraphQLErrors_SurfacesErrorsNotHttpStatus()
    {
        // GraphQL backends may return a structured `errors` envelope alongside a non-2xx status.
        // The errors (and their code -> status mapping) must win over the raw HTTP status so the
        // client still gets the structured GraphQL error.
        var handler = new StubHandler(
            HttpStatusCode.BadRequest,
            """{"errors":[{"message":"Field 'x' not found","extensions":{"code":"NOT_FOUND"}}]}""",
            "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ x }", null, "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Errors);
        Assert.Single(result.Errors!);
        Assert.Equal("Field 'x' not found", result.Errors![0].Message);
        Assert.Equal(404, result.MappedStatusCode); // NOT_FOUND -> 404, not the HTTP 400
    }

    [Fact]
    public async Task GraphQL_BackendNetworkFailure_ReturnsFromBackendError()
    {
        var handler = new ThrowingHandler(new HttpRequestException("connect failed"));
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ x }", null, "x",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.NetworkError, result.ErrorType);
        Assert.Equal(502, result.HttpStatusCode);
    }

    [Fact]
    public async Task ReadBounded_CharsetInContentType_DecodesUsingThatEncoding()
    {
        // Body is encoded as ISO-8859-1; UTF-8 decoding would mangle the high-byte character.
        // Use ä (0xE4 in latin-1) inside a JSON string so the envelope is still parseable.
        var iso = Encoding.GetEncoding("iso-8859-1");
        var bodyBytes = iso.GetBytes("""{"data":{"product":{"id":"1","name":"Käse"}}}""".Replace("\\u00e4", "ä"));
        var handler = new ByteHandler(HttpStatusCode.OK, bodyBytes, "application/json; charset=iso-8859-1");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ product { id name } }", null, "product",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal("Käse", result.Data!.Name);
    }

    [Fact]
    public async Task ReadBounded_InvalidCharset_FallsBackToUtf8()
    {
        // Content-Type announces a charset that Encoding.GetEncoding refuses; the reader
        // must catch the ArgumentException and fall back to UTF-8 rather than failing.
        var bytes = Encoding.UTF8.GetBytes("""{"data":{"product":{"id":"1","name":"x"}}}""");
        var handler = new ByteHandler(HttpStatusCode.OK, bytes, "application/json; charset=definitely-not-a-real-encoding");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ product { id name } }", null, "product",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal("x", result.Data!.Name);
    }

    [Fact]
    public async Task ReadBounded_MaxBackendResponseBytesZero_DisablesCap()
    {
        // MaxBackendResponseBytes <= 0 must take the bypass branch that calls
        // ReadAsStringAsync without any size check. A 1MB body must come back intact.
        var bigBody = "{\"data\":{\"product\":{\"id\":\"1\",\"name\":\"" + new string('a', 1024 * 1024) + "\"}}}";
        var handler = new StubHandler(HttpStatusCode.OK, bigBody, "application/json");
        var caller = CreateCaller(handler, maxBackendResponseBytes: 0);

        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/graphql" };
        var result = await caller.CallGraphQLAsync<Product>(
            request, "{ product { id name } }", null, "product",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(1024 * 1024, result.Data!.Name.Length);
    }

    // ===========================================================================
    // CallRawAsync — no-body variant
    // ===========================================================================

    [Fact]
    public async Task RawNoBody_SuccessfulCall_ReturnsRawResultWithResponse()
    {
        var handler = new StubHandler(HttpStatusCode.OK, "binary-payload", "application/octet-stream");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/download" };
        using var result = await caller.CallRawAsync(request, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.StatusCode);
        Assert.NotNull(result.Response);
        Assert.Equal("application/octet-stream", result.ContentType);
        var body = await result.Response!.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal("binary-payload", body);

        // GET request with no body sent
        Assert.Equal(HttpMethod.Get, handler.LastRequest!.Method);
        Assert.Null(handler.LastRequest.Content);
    }

    [Fact]
    public async Task RawNoBody_BackendReturns4xx_PassesResponseThroughUnwrapped()
    {
        // The raw path is intentionally permissive: any HTTP response that came back from
        // the backend (including 4xx/5xx) is wrapped in RawBackendResult.Success so the
        // caller can stream the body and status back to the client unchanged. Only
        // network/timeout/auth failures take the IsSuccess=false branch.
        var handler = new StubHandler(HttpStatusCode.NotFound, "missing", "text/plain");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/missing" };
        using var result = await caller.CallRawAsync(request, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
        Assert.NotNull(result.Response);
        var body = await result.Response!.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal("missing", body);
    }

    [Fact]
    public async Task RawNoBody_NetworkFailure_ReturnsNetworkFailure()
    {
        var handler = new ThrowingHandler(new HttpRequestException("connect refused"));
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x" };
        using var result = await caller.CallRawAsync(request, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.NetworkError, result.ErrorType);
        Assert.Equal(502, result.StatusCode);
        Assert.Equal("Backend service unavailable", result.Error);
    }

    [Fact]
    public async Task RawNoBody_Timeout_ReturnsTimeoutFailure()
    {
        var handler = new ThrowingHandler(new TaskCanceledException("timed out", new TimeoutException()));
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/slow" };
        using var result = await caller.CallRawAsync(request, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.Timeout, result.ErrorType);
        Assert.Equal(504, result.StatusCode);
        Assert.Equal("Request timed out", result.Error);
    }

    [Fact]
    public async Task RawNoBody_GenericException_ReturnsUnknownError()
    {
        var handler = new ThrowingHandler(new InvalidOperationException("boom"));
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x" };
        using var result = await caller.CallRawAsync(request, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.Unknown, result.ErrorType);
        Assert.Equal(500, result.StatusCode);
        Assert.Equal("An unexpected error occurred", result.Error);
    }

    [Fact]
    public async Task RawNoBody_CallerCancellation_PropagatesInsteadOfMappingToError()
    {
        // A cancelled caller token (client disconnect or a global request timeout) must surface
        // as cancellation, not be laundered into a 500/504 RawBackendResult that downstream code
        // reads as a degraded backend. Distinct from RawNoBody_Timeout_ReturnsTimeoutFailure,
        // whose TaskCanceledException carries the internal HttpClient.Timeout token, not this one.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var handler = new ThrowingHandler(new OperationCanceledException(cts.Token));
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x" };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => caller.CallRawAsync(request, cts.Token));
    }

    [Fact]
    public async Task Call_CallerCancellation_PropagatesInsteadOfMappingToError()
    {
        // Same guard on the standard (non-raw) send path through AttemptSendAsync.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var handler = new ThrowingHandler(new OperationCanceledException(cts.Token));
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x" };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => caller.CallAsync<Product>(request, cts.Token));
    }

    // ===========================================================================
    // Deserialization failure mapping (identical control flow in Debug and Release)
    // ===========================================================================

    [Fact]
    public async Task Call_MalformedJsonBody_ReturnsInvalidResponse_DoesNotThrow()
    {
        // Previously the typed path let JsonException propagate in Debug and only mapped to
        // InvalidResponse in Release - so the test suite (Debug) never covered this branch.
        // It now behaves identically in both configs.
        var handler = new StubHandler(HttpStatusCode.OK, "{ this is not valid json", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x" };
        var result = await caller.CallAsync<Product>(request, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.InvalidResponse, result.ErrorType);
    }

    [Fact]
    public async Task CallObject_MalformedJsonBody_ReturnsInvalidResponse_DoesNotThrow()
    {
        var handler = new StubHandler(HttpStatusCode.OK, "{ broken", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x" };
        var result = await caller.CallAsync(request, typeof(Product), TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.InvalidResponse, result.ErrorType);
    }

    // ===========================================================================
    // Bounded reader on the typed path (the OOM cap, now that the typed send uses
    // ResponseHeadersRead like the raw path)
    // ===========================================================================

    [Fact]
    public async Task Call_ResponseExceedsMaxBytes_ReturnsInvalidResponse()
    {
        var oversized = "\"" + new string('a', 5000) + "\"";
        var handler = new StubHandler(HttpStatusCode.OK, oversized, "application/json");
        var caller = CreateCaller(handler, maxBackendResponseBytes: 1024);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x" };
        var result = await caller.CallAsync<string>(request, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.InvalidResponse, result.ErrorType);
    }

    // ===========================================================================
    // Cancellation threaded into the backend auth handler
    // ===========================================================================

    [Fact]
    public async Task Call_ThreadsRequestCancellationTokenIntoAuthHandler()
    {
        // Token-exchange handlers do an STS round-trip in ApplyAuthAsync; that round-trip must
        // honour the request deadline rather than receiving CancellationToken.None.
        var capture = new TokenCapturingAuthHandler("Capture");
        var handler = new StubHandler(HttpStatusCode.OK, "{}", "application/json");
        var caller = CreateCaller(handler, authHandler: capture);

        using var cts = new CancellationTokenSource();
        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x", BackendAuthPolicy = "Capture" };
        await caller.CallAsync<Product>(request, cts.Token);

        Assert.True(capture.CapturedToken.CanBeCanceled);
        cts.Cancel();
        Assert.True(capture.CapturedToken.IsCancellationRequested);
    }

    // ===========================================================================
    // Backend auth misconfiguration maps to ConfigurationError, not a user 401
    // ===========================================================================

    [Fact]
    public async Task Call_AuthHandlerThrowsConfigurationException_MapsToConfigurationError_Not401()
    {
        // A BackendAuthConfigurationException (e.g. token exchange with no audience) is a
        // server-side misconfiguration. It must surface as a 5xx-class ConfigurationError so
        // operators don't mistake it for a genuine user-credential rejection (401).
        var handler = new StubHandler(HttpStatusCode.OK, "{}", "application/json");
        var caller = CreateCaller(handler, authHandler: new ConfigThrowingAuthHandler("Misconfigured"));

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x", BackendAuthPolicy = "Misconfigured" };
        var result = await caller.CallAsync<Product>(request, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.ConfigurationError, result.ErrorType);
        Assert.NotEqual(BackendErrorType.AuthenticationError, result.ErrorType);
        Assert.Null(handler.LastRequest); // the backend was never called
    }

    // ===========================================================================
    // Response disposal (mandatory under ResponseHeadersRead)
    // ===========================================================================

    [Fact]
    public async Task Call_DisposesResponseAfterDeserialize()
    {
        var handler = new DisposeTrackingHandler(HttpStatusCode.OK, "{}", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x" };
        await caller.CallAsync<Product>(request, TestContext.Current.CancellationToken);

        Assert.True(handler.ContentDisposed);
    }

    // ===========================================================================
    // Per-attempt span shape + URL sanitization in spans and logs
    // ===========================================================================

    [Fact]
    public async Task Call_EmitsSingleBackendSpan_WithSanitizedUrlAndRefreshRetryFalse()
    {
        // The Porta ActivitySource is process-global: ActivityStopped can fire concurrently for spans
        // emitted by other tests (a List.Add would corrupt under that race, and an unfiltered
        // Assert.Single would count their spans). Collect into a thread-safe bag and scope the
        // assertion to this test's own backend call via its unique sanitized URL.
        var stopped = new System.Collections.Concurrent.ConcurrentBag<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == PortaActivitySource.Source.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = stopped.Add,
        };
        ActivitySource.AddActivityListener(listener);

        var handler = new StubHandler(HttpStatusCode.OK, "{}", "application/json");
        var caller = CreateCaller(handler);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/users?token=secret" };
        await caller.CallAsync<Product>(request, TestContext.Current.CancellationToken);

        var span = Assert.Single(stopped, s =>
            (s.GetTagItem(PortaActivitySource.Tags.HttpUrl)?.ToString() ?? "").Contains("backend.test/users"));
        Assert.Equal(ActivityStatusCode.Ok, span.Status);
        Assert.Equal(false, span.GetTagItem("bff.backend.refresh_retry"));
        var taggedUrl = span.GetTagItem(PortaActivitySource.Tags.HttpUrl)?.ToString() ?? "";
        Assert.DoesNotContain("token=secret", taggedUrl);
        Assert.Contains("https://backend.test/users", taggedUrl);
    }

    [Fact]
    public async Task Call_TelemetryDisabled_EmitsNoBackendSpan()
    {
        // EnableTelemetry=false must fully opt out of Porta's own backend telemetry: with the
        // option off, SendRequestAsync must not start a backend ActivitySource span at all
        // (regression - backend spans previously ran regardless of the option).
        var stopped = new System.Collections.Concurrent.ConcurrentBag<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == PortaActivitySource.Source.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = stopped.Add,
        };
        ActivitySource.AddActivityListener(listener);

        var handler = new StubHandler(HttpStatusCode.OK, "{}", "application/json");
        var caller = CreateCaller(handler, enableTelemetry: false);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/telemetry-off-marker" };
        await caller.CallAsync<Product>(request, TestContext.Current.CancellationToken);

        // The call still succeeded - only the instrumentation was suppressed.
        Assert.NotNull(handler.LastRequest);
        Assert.DoesNotContain(stopped, s =>
            (s.GetTagItem(PortaActivitySource.Tags.HttpUrl)?.ToString() ?? "").Contains("telemetry-off-marker"));
    }

    [Fact]
    public async Task Call_TelemetryDisabled_LeavesAmbientReverseProxyTraceIntact()
    {
        // Disabling Porta telemetry suppresses *Porta's* spans, but it must never disturb the
        // ambient trace an upstream reverse proxy (or host instrumentation) established: that
        // activity stays current and running so the external trace is not silently broken and
        // still propagates to the backend.
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "ReverseProxy.Test",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listener);

        using var proxySource = new ActivitySource("ReverseProxy.Test");
        using var proxySpan = proxySource.StartActivity("incoming", ActivityKind.Server);
        Assert.NotNull(proxySpan);

        var handler = new StubHandler(HttpStatusCode.OK, "{}", "application/json");
        var caller = CreateCaller(handler, enableTelemetry: false);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/x" };
        await caller.CallAsync<Product>(request, TestContext.Current.CancellationToken);

        // Porta neither replaced the reverse-proxy span with its own backend span nor stopped it:
        // it is still Activity.Current (Same) and still running (zero Duration until its own Stop).
        Assert.Same(proxySpan, Activity.Current);
        Assert.Equal(TimeSpan.Zero, proxySpan!.Duration);
        Assert.NotNull(handler.LastRequest);
    }

    [Fact]
    public async Task Call_LogsSanitizedUrl_WithoutQueryString()
    {
        var capture = new CapturingLogger();
        var handler = new StubHandler(HttpStatusCode.OK, "{}", "application/json");
        var caller = CreateCaller(handler, logger: capture);

        var request = new BackendRequest { Method = "GET", Url = "https://backend.test/users?token=secret" };
        await caller.CallAsync<Product>(request, TestContext.Current.CancellationToken);

        Assert.NotEmpty(capture.Messages);
        Assert.All(capture.Messages, m => Assert.DoesNotContain("token=secret", m));
        Assert.Contains(capture.Messages, m => m.Contains("https://backend.test/users"));
    }

    [Fact]
    public async Task RawNoBody_CustomHeadersOnRequest_ArePropagated()
    {
        var handler = new StubHandler(HttpStatusCode.OK, "ok", "text/plain");
        var caller = CreateCaller(handler);

        var request = new BackendRequest
        {
            Method = "GET",
            Url = "https://backend.test/x",
            Headers = new Dictionary<string, string>
            {
                ["X-Trace-Id"] = "abc-123",
                ["Accept"] = "text/plain"
            }
        };
        using var result = await caller.CallRawAsync(request, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.True(handler.LastRequest!.Headers.TryGetValues("X-Trace-Id", out var traceVals));
        Assert.Equal("abc-123", traceVals!.Single());
        Assert.True(handler.LastRequest.Headers.TryGetValues("Accept", out var acceptVals));
        Assert.Equal("text/plain", acceptVals!.Single());
    }

    [Fact]
    public async Task RawNoBody_AuthHandlerThrows_ReturnsAuthError()
    {
        var handler = new StubHandler(HttpStatusCode.OK, "ok", "text/plain");
        var caller = CreateCaller(handler, authHandler: new ThrowingAuthHandler("Throwing"));

        var request = new BackendRequest
        {
            Method = "GET",
            Url = "https://backend.test/x",
            BackendAuthPolicy = "Throwing"
        };
        using var result = await caller.CallRawAsync(request, TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.AuthenticationError, result.ErrorType);
        Assert.Equal(401, result.StatusCode);
        Assert.StartsWith("Authentication failed:", result.Error);
        // Backend was never called.
        Assert.Null(handler.LastRequest);
    }

    // ===========================================================================
    // CallRawAsync — body-stream variant
    // ===========================================================================

    [Fact]
    public async Task RawWithBody_ForwardsBodyStreamAndContentType()
    {
        var handler = new StubHandler(HttpStatusCode.OK, "ack", "application/json");
        var caller = CreateCaller(handler);

        var payload = Encoding.UTF8.GetBytes("""{"hello":"world"}""");
        using var bodyStream = new MemoryStream(payload);
        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/upload" };

        using var result = await caller.CallRawAsync(
            request,
            bodyStream,
            "application/json",
            TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.NotNull(handler.LastRequest!.Content);
        Assert.Equal("application/json", handler.LastRequest.Content!.Headers.ContentType?.MediaType);
        var forwarded = await handler.LastRequest.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal("""{"hello":"world"}""", forwarded);
    }

    [Theory]
    [InlineData("application/json; charset=utf-8")]
    [InlineData("text/plain; charset=iso-8859-1")]
    [InlineData("multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW")]
    public async Task RawWithBody_ParameterizedContentType_DoesNotThrowAndPreservesMediaType(string contentType)
    {
        // Regression: the inbound Content-Type routinely carries parameters (charset, multipart
        // boundary). new MediaTypeHeaderValue(string) rejects those with a FormatException, turning
        // any form post / charset-tagged body into a 500. The fix parses the full header value.
        var handler = new StubHandler(HttpStatusCode.OK, "ack", "application/json");
        var caller = CreateCaller(handler);

        var payload = Encoding.UTF8.GetBytes("payload");
        using var bodyStream = new MemoryStream(payload);
        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/upload" };

        using var result = await caller.CallRawAsync(
            request,
            bodyStream,
            contentType,
            TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        // The media type round-trips; parameters are parsed rather than rejected.
        var expectedMediaType = MediaTypeHeaderValue.Parse(contentType).MediaType;
        Assert.Equal(expectedMediaType, handler.LastRequest!.Content!.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task RawWithBody_NetworkFailure_ReturnsNetworkFailure()
    {
        var handler = new ThrowingHandler(new HttpRequestException("DNS fail"));
        var caller = CreateCaller(handler);

        using var bodyStream = new MemoryStream([1, 2, 3]);
        var request = new BackendRequest { Method = "POST", Url = "https://backend.test/upload" };

        using var result = await caller.CallRawAsync(
            request, bodyStream, "application/octet-stream",
            TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(BackendErrorType.NetworkError, result.ErrorType);
    }

    // ===========================================================================
    // Helpers
    // ===========================================================================

    private static BackendCaller CreateCaller(
        HttpMessageHandler handler,
        long maxBackendResponseBytes = 10 * 1024 * 1024,
        IBackendAuthHandler? authHandler = null,
        ILogger<BackendCaller>? logger = null,
        bool enableTelemetry = true)
    {
        var registry = new BackendAuthHandlerRegistry();
        registry.Register(new NoneAuthHandler());
        if (authHandler != null)
        {
            registry.Register(authHandler);
        }

        var httpClientFactory = new SingleHandlerHttpClientFactory(handler);
        var options = Options.Create(new PortaCoreOptions
        {
            MaxBackendResponseBytes = maxBackendResponseBytes,
            EnableTelemetry = enableTelemetry,
        });

        return new BackendCaller(
            httpClientFactory,
            registry,
            new ContentSerializer(),
            metrics: null,
            logger: logger ?? NullLogger<BackendCaller>.Instance,
            coreOptions: options);
    }

    private sealed record Product
    {
        public string Id { get; init; } = "";
        public string Name { get; init; } = "";
    }

    private sealed class SingleHandlerHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    /// <summary>
    /// Captures the outbound request and returns a canned response with the given body
    /// and content type. Set <see cref="OverrideContentLength"/> to forge a Content-Length
    /// header that doesn't match the actual body length (used for the size-cap tests).
    /// </summary>
    private sealed class StubHandler(HttpStatusCode status, string body, string contentType) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public string? LastBody { get; private set; }

        /// <summary>
        /// null = use the actual body length (HttpClient default).
        /// -1 = explicitly suppress the Content-Length header.
        /// any other value = forge that header value.
        /// </summary>
        public long? OverrideContentLength { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            if (request.Content != null)
            {
                LastBody = await request.Content.ReadAsStringAsync(cancellationToken);
            }

            HttpContent content;
            if (OverrideContentLength == -1L)
            {
                // Use a stream content with an unknown length so Content-Length is suppressed.
                var bytes = Encoding.UTF8.GetBytes(body);
                content = new StreamContent(new MemoryStream(bytes));
                content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
                content.Headers.ContentLength = null;
            }
            else
            {
                content = new StringContent(body, Encoding.UTF8, contentType);
                if (OverrideContentLength.HasValue)
                {
                    content.Headers.ContentLength = OverrideContentLength.Value;
                }
            }

            return new HttpResponseMessage(status) { Content = content };
        }
    }

    /// <summary>
    /// Sends a response with caller-supplied raw bytes so the test can assert charset
    /// handling without relying on StringContent's UTF-8 default.
    /// </summary>
    private sealed class ByteHandler(HttpStatusCode status, byte[] body, string contentTypeWithCharset) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var content = new ByteArrayContent(body);
            content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentTypeWithCharset);
            return Task.FromResult(new HttpResponseMessage(status) { Content = content });
        }
    }

    private sealed class ThrowingHandler(Exception exceptionToThrow) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => throw exceptionToThrow;
    }

    private sealed class ThrowingAuthHandler(string policy) : IBackendAuthHandler
    {
        public string PolicyName { get; } = policy;
        public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
            => throw new InvalidOperationException("auth handler failed");
    }

    /// <summary>Throws the config-error exception so the caller maps it to ConfigurationError.</summary>
    private sealed class ConfigThrowingAuthHandler(string policy) : IBackendAuthHandler
    {
        public string PolicyName { get; } = policy;
        public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
            => throw new BackendAuthConfigurationException("token exchange has no audience configured");
    }

    /// <summary>Records the <see cref="CancellationToken"/> handed to the auth handler.</summary>
    private sealed class TokenCapturingAuthHandler(string policy) : IBackendAuthHandler
    {
        public string PolicyName { get; } = policy;
        public CancellationToken CapturedToken { get; private set; }

        public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
        {
            CapturedToken = context.CancellationToken;
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Returns a response whose content flags when it is disposed, so a test can assert the
    /// caller disposes the <see cref="HttpResponseMessage"/> (which cascades to its content).
    /// </summary>
    private sealed class DisposeTrackingHandler(HttpStatusCode status, string body, string contentType) : HttpMessageHandler
    {
        public bool ContentDisposed => _content?.Disposed ?? false;
        private TrackingContent? _content;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _content = new TrackingContent(Encoding.UTF8.GetBytes(body), contentType);
            return Task.FromResult(new HttpResponseMessage(status) { Content = _content });
        }

        private sealed class TrackingContent : ByteArrayContent
        {
            public bool Disposed { get; private set; }

            public TrackingContent(byte[] content, string contentType) : base(content)
            {
                Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
            }

            protected override void Dispose(bool disposing)
            {
                Disposed = true;
                base.Dispose(disposing);
            }
        }
    }

    /// <summary>Captures formatted log messages so tests can assert on what was written.</summary>
    private sealed class CapturingLogger : ILogger<BackendCaller>
    {
        public List<string> Messages { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Messages.Add(formatter(state, exception));

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
