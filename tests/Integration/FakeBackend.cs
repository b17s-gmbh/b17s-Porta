using System.Collections.Concurrent;
using System.Text;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Integration;

/// <summary>
/// In-process backend host. Tests declare routes inline, every received
/// request is recorded (method, path, query, headers, body), and the
/// <see cref="BackchannelHandler"/> can be wired into the BFF's BackendCaller
/// HttpClient so production code reaches this server over real HTTP semantics.
/// </summary>
/// <remarks>
/// Sibling to <see cref="FakeIdp"/>. Lives behind a <see cref="TestServer"/>; no
/// sockets are opened. Use <see cref="MapGet"/>/<see cref="MapPost"/>/etc. to
/// declare routes before resolving <see cref="BackchannelHandler"/>.
/// </remarks>
public sealed class FakeBackend : IDisposable
{
    private readonly List<EndpointRegistration> _registrations = [];
    private readonly ConcurrentQueue<RecordedRequest> _received = new();
    private IHost? _host;
    private TestServer? _server;
    private HttpMessageHandler? _handler;

    /// <summary>
    /// Authority used for the backend's base URL. Tests build full URLs as
    /// <c>{BaseAddress}/some/path</c> when configuring Porta endpoints.
    /// </summary>
    public string BaseAddress { get; }

    public FakeBackend(string baseAddress = "http://backend.test")
    {
        BaseAddress = baseAddress.TrimEnd('/');
    }

    /// <summary>
    /// Requests received in order. Lets a test assert that the backend saw the
    /// exact request the BFF was supposed to send (path, query, headers, body).
    /// </summary>
    public IReadOnlyList<RecordedRequest> ReceivedRequests => _received.ToArray();

    /// <summary>
    /// HTTP message handler that routes outbound requests to this server.
    /// Plug this into the BackendCaller's HttpClient via
    /// <c>ConfigurePrimaryHttpMessageHandler(() =&gt; backend.BackchannelHandler)</c>.
    /// Building it eagerly seals the route table, so all <see cref="MapGet"/>
    /// /etc. calls must complete first.
    /// </summary>
    public HttpMessageHandler BackchannelHandler => GetOrStart().Handler;

    public FakeBackend MapGet(string pattern, RequestDelegate handler)
        => Map("GET", pattern, handler);

    public FakeBackend MapPost(string pattern, RequestDelegate handler)
        => Map("POST", pattern, handler);

    public FakeBackend MapPut(string pattern, RequestDelegate handler)
        => Map("PUT", pattern, handler);

    public FakeBackend MapDelete(string pattern, RequestDelegate handler)
        => Map("DELETE", pattern, handler);

    public FakeBackend MapPatch(string pattern, RequestDelegate handler)
        => Map("PATCH", pattern, handler);

    /// <summary>
    /// Registers a handler for the given HTTP method and route pattern.
    /// Use "*" for the method to match any verb.
    /// </summary>
    public FakeBackend Map(string method, string pattern, RequestDelegate handler)
    {
        if (_host is not null)
        {
            throw new InvalidOperationException(
                "FakeBackend route table is sealed once BackchannelHandler has been resolved.");
        }
        _registrations.Add(new EndpointRegistration(method.ToUpperInvariant(), pattern, handler));
        return this;
    }

    private (HttpMessageHandler Handler, TestServer Server) GetOrStart()
    {
        if (_handler is not null && _server is not null)
        {
            return (_handler, _server);
        }

        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services => services.AddRouting());
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        foreach (var reg in _registrations)
                        {
                            RegisterEndpoint(endpoints, reg);
                        }
                    });
                });
            });

        _host = hostBuilder.Start();
        _server = _host.GetTestServer();
        _server.BaseAddress = new Uri(BaseAddress);
        _handler = _server.CreateHandler();
        return (_handler, _server);
    }

    private void RegisterEndpoint(IEndpointRouteBuilder endpoints, EndpointRegistration reg)
    {
        var wrapped = WrapWithRecording(reg.Handler);
        _ = reg.Method switch
        {
            "GET" => endpoints.MapGet(reg.Pattern, wrapped),
            "POST" => endpoints.MapPost(reg.Pattern, wrapped),
            "PUT" => endpoints.MapPut(reg.Pattern, wrapped),
            "DELETE" => endpoints.MapDelete(reg.Pattern, wrapped),
            "PATCH" => endpoints.MapPatch(reg.Pattern, wrapped),
            "*" => endpoints.MapMethods(reg.Pattern,
                ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], wrapped),
            _ => throw new InvalidOperationException($"Unsupported method: {reg.Method}")
        };
    }

    private RequestDelegate WrapWithRecording(RequestDelegate inner) => async context =>
    {
        var recorded = await RecordedRequest.CaptureAsync(context);
        _received.Enqueue(recorded);
        await inner(context);
    };

    public void Dispose()
    {
        _handler?.Dispose();
        _server?.Dispose();
        _host?.Dispose();
    }

    private sealed record EndpointRegistration(string Method, string Pattern, RequestDelegate Handler);
}

/// <summary>
/// Snapshot of an inbound request observed by <see cref="FakeBackend"/>.
/// </summary>
public sealed class RecordedRequest
{
    public required string Method { get; init; }
    public required string Path { get; init; }
    public required string QueryString { get; init; }
    public required IReadOnlyDictionary<string, string[]> Headers { get; init; }
    public required string Body { get; init; }
    public required byte[] BodyBytes { get; init; }

    /// <summary>
    /// Convenience: returns the value of <c>Authorization</c> (first header value)
    /// or <c>null</c> if the request didn't send one. Tests assert on this often
    /// enough to deserve a shortcut.
    /// </summary>
    public string? Authorization
        => Headers.TryGetValue("Authorization", out var v) && v.Length > 0 ? v[0] : null;

    internal static async Task<RecordedRequest> CaptureAsync(HttpContext context)
    {
        // Buffer the body so the handler can still read it after recording.
        context.Request.EnableBuffering();
        using var ms = new MemoryStream();
        await context.Request.Body.CopyToAsync(ms);
        var bytes = ms.ToArray();
        context.Request.Body.Position = 0;

        var headers = context.Request.Headers
            .ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.Where(v => v is not null).Select(v => v!).ToArray(),
                StringComparer.OrdinalIgnoreCase);

        return new RecordedRequest
        {
            Method = context.Request.Method,
            Path = context.Request.Path.Value ?? string.Empty,
            QueryString = context.Request.QueryString.Value ?? string.Empty,
            Headers = headers,
            Body = Encoding.UTF8.GetString(bytes),
            BodyBytes = bytes,
        };
    }
}
