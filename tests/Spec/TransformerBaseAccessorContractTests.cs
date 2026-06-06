using System.IO;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;

namespace b17s.Porta.Tests.Spec;

/// <summary>
/// Spec §4 / Regression #9 — singular accessors return the FIRST value (never comma-joined);
/// plural accessors return all values. §2.6 — RequestHeaders use a case-insensitive comparer.
/// </summary>
public class TransformerBaseAccessorContractTests
{
    private sealed class ProbeTransformer : TransformerBase<string>
    {
        public override Task<string> TransformAsync(TransformerContext context) => Task.FromResult(string.Empty);

        public string? Query(TransformerContext c, string k) => GetQueryParameter(c, k);
        public IEnumerable<string> QueryAll(TransformerContext c, string k) => GetQueryValues(c, k);
        public string? Header(TransformerContext c, string k) => GetRequestHeader(c, k);
        public IEnumerable<string> HeaderAll(TransformerContext c, string k) => GetRequestHeaders(c, k);
    }

    private static TransformerContext BuildContext()
    {
        return new TransformerContext
        {
            HttpContext = new DefaultHttpContext(),
            AuthContext = AuthenticationContext.Unauthenticated(),
            CancellationToken = CancellationToken.None,
            RouteValues = new Dictionary<string, object?>(),
            QueryParameters = new Dictionary<string, StringValues>
            {
                ["id"] = new StringValues(["a", "b"]),
            },
            RequestHeaders = new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase)
            {
                ["X-Test"] = new StringValues(["first", "second"]),
            },
            BackendCaller = new NotCalledBackendCaller(),
            Properties = new Dictionary<string, object>(),
            Logger = NullLogger.Instance,
        };
    }

    [Fact]
    public void GetQueryParameter_ReturnsFirstValue_NotCommaJoined()
    {
        var probe = new ProbeTransformer();
        var value = probe.Query(BuildContext(), "id");

        Assert.Equal("a", value);
    }

    [Fact]
    public void GetQueryValues_ReturnsAllValues()
    {
        var probe = new ProbeTransformer();
        Assert.Equal(["a", "b"], probe.QueryAll(BuildContext(), "id"));
    }

    [Fact]
    public void GetQueryParameter_AbsentKey_ReturnsNull()
    {
        var probe = new ProbeTransformer();
        Assert.Null(probe.Query(BuildContext(), "missing"));
    }

    [Fact]
    public void GetRequestHeader_ReturnsFirstValue_NotCommaJoined()
    {
        var probe = new ProbeTransformer();
        var value = probe.Header(BuildContext(), "X-Test");

        Assert.Equal("first", value);
    }

    [Fact]
    public void GetRequestHeaders_ReturnsAllValues()
    {
        var probe = new ProbeTransformer();
        Assert.Equal(["first", "second"], probe.HeaderAll(BuildContext(), "X-Test"));
    }

    [Fact]
    public void GetRequestHeader_IsCaseInsensitive()
    {
        // §2.6 — HTTP header names are case-insensitive.
        var probe = new ProbeTransformer();
        Assert.Equal("first", probe.Header(BuildContext(), "x-test"));
    }
}

/// <summary>A backend caller that must never be invoked; present only to satisfy required context wiring.</summary>
internal sealed class NotCalledBackendCaller : IBackendCaller
{
    public Task<BackendResult<TResponse>> CallAsync<TResponse>(BackendRequest request, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<BackendResult<TResponse>> CallAsync<TRequest, TResponse>(BackendRequest request, TRequest body, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<BackendResult> CallAsync(BackendRequest request, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<BackendResult> CallAsync<TRequest>(BackendRequest request, TRequest body, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<BackendObjectResult> CallAsync(BackendRequest request, Type responseType, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<BackendObjectResult> CallWithBodyAsync(BackendRequest request, object body, Type responseType, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<GraphQLResult<TResponse>> CallGraphQLAsync<TResponse>(BackendRequest request, string query, object? variables, string dataPath, string? operationName = null, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public Task<RawBackendResult> CallRawAsync(BackendRequest request, CancellationToken cancellationToken)
        => throw new NotSupportedException();

    public Task<RawBackendResult> CallRawAsync(BackendRequest request, Stream requestBody, string contentType, CancellationToken cancellationToken)
        => throw new NotSupportedException();
}
