using System.Diagnostics;

using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Middleware;

/// <summary>
/// Opt-in request-lifecycle instrumentation. When registered (via
/// <c>app.UsePortaTelemetry()</c>) this middleware emits, for every request that flows through it:
/// the <c>bff.request</c> span, the <c>bff.requests.active</c> in-flight gauge, and the
/// <c>bff.request.duration</c>, <c>bff.request.size</c>, and <c>bff.response.size</c> metrics.
/// <para>
/// It is a no-op pass-through when <see cref="PortaCoreOptions.EnableTelemetry"/> is <c>false</c>,
/// mirroring the per-endpoint instrumentation so a single switch disables all of Porta's own
/// telemetry. Porta has no other always-on middleware, so this is the only place a true
/// whole-pipeline request span/metric can be produced; register it as early as possible (before
/// <c>UseRouting</c>) so it brackets the entire request - the matched route template is read back
/// from the resolved endpoint after the pipeline runs.
/// </para>
/// </summary>
public sealed class PortaTelemetryMiddleware(RequestDelegate next, IOptions<PortaCoreOptions> coreOptions, PortaMetrics metrics)
{
    private readonly bool _enabled = coreOptions.Value.EnableTelemetry;

    /// <summary>
    /// Brackets the rest of the pipeline with request-lifecycle telemetry. See the type summary.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        if (!_enabled)
        {
            await next(context);
            return;
        }

        var method = context.Request.Method;
        var requestSize = context.Request.ContentLength;

        // Fixed category activity name; HTTP detail lives on tags so span cardinality stays bounded.
        using var activity = PortaActivitySource.Source.StartActivity(
            PortaActivitySource.Activities.PortaRequest, ActivityKind.Server);
        activity?.SetTag(PortaActivitySource.Tags.Component, "request");
        activity?.SetTag(PortaActivitySource.Tags.HttpMethod, method);

        // Count bytes written to the response body. Setting HttpResponse.Body swaps in a response-body
        // feature wrapping this stream, so writes via either Body or BodyWriter are measured.
        var originalBody = context.Response.Body;
        var countingBody = new CountingStream(originalBody);
        context.Response.Body = countingBody;

        metrics.IncrementActiveRequests();
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await next(context);
        }
        finally
        {
            stopwatch.Stop();
            context.Response.Body = originalBody;
            metrics.DecrementActiveRequests();

            var status = context.Response.StatusCode;
            // Low-cardinality route TEMPLATE (e.g. /api/users/{id}), resolved after routing ran in
            // next(). Requests that matched no route collapse to a single "unmatched" series rather
            // than emitting one time-series per concrete path.
            var route = ResolveRouteTemplate(context);

            activity?.SetTag(PortaActivitySource.Tags.HttpRoute, route);
            activity?.SetTag(PortaActivitySource.Tags.HttpStatusCode, status);
            if (status >= 500)
            {
                activity?.SetStatus(ActivityStatusCode.Error);
            }

            metrics.RecordRequestDuration(stopwatch.Elapsed.TotalMilliseconds, method, route, status);
            if (requestSize.HasValue)
            {
                metrics.RecordRequestSize(requestSize.Value, method);
            }
            metrics.RecordResponseSize(countingBody.BytesWritten, status);
        }
    }

    private static string ResolveRouteTemplate(HttpContext context)
    {
        if (context.GetEndpoint() is RouteEndpoint routeEndpoint
            && routeEndpoint.RoutePattern.RawText is { Length: > 0 } template)
        {
            return template;
        }

        return "unmatched";
    }

    /// <summary>
    /// Pass-through stream that tallies the number of bytes written to the wrapped response body,
    /// without buffering. Read/seek are unsupported - a response body is write-only here.
    /// </summary>
    private sealed class CountingStream(Stream inner) : Stream
    {
        public long BytesWritten { get; private set; }

        public override bool CanWrite => inner.CanWrite;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => inner.Position;
            set => throw new NotSupportedException();
        }

        public override void Flush() => inner.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        public override void Write(byte[] buffer, int offset, int count)
        {
            BytesWritten += count;
            inner.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            BytesWritten += buffer.Length;
            inner.Write(buffer);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            BytesWritten += count;
            return inner.WriteAsync(buffer, offset, count, cancellationToken);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            BytesWritten += buffer.Length;
            return inner.WriteAsync(buffer, cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
