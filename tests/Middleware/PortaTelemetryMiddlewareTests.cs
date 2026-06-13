using System.Diagnostics;
using System.Net.Http;
using System.Text;

using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Telemetry;
using b17s.Porta.Tests.Telemetry;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Middleware;

[Collection(PortaActivitySourceCollection.Name)]
public sealed class PortaTelemetryMiddlewareTests
{
    [Fact]
    public async Task RecordsRequestLifecycle_Duration_Sizes_ActiveGauge_AndSpan()
    {
        using var harness = RecordingMetricsHarness.Create();
        var stopped = new System.Collections.Concurrent.ConcurrentBag<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == PortaActivitySource.Source.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = stopped.Add,
        };
        ActivitySource.AddActivityListener(listener);

        using var host = await CreateHostAsync(harness.Metrics, enableTelemetry: true);
        var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync(
            "/echo/42",
            new StringContent("request-body", Encoding.UTF8),
            TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();

        var durations = harness.Drain("bff.request.duration");
        var duration = Assert.Single(durations);
        Assert.Equal("POST", duration.Tags["method"]);
        Assert.Equal("/echo/{id}", duration.Tags["route"]);
        Assert.Equal(200, Convert.ToInt32(duration.Tags["status_code"]));

        var reqSize = Assert.Single(harness.Drain("bff.request.size"));
        Assert.Equal("request-body".Length, Convert.ToInt32(reqSize.Value));

        var respSize = Assert.Single(harness.Drain("bff.response.size"));
        Assert.Equal("response-body".Length, Convert.ToInt32(respSize.Value));

        // Incremented on entry, decremented in finally - nets back to zero once the request completes.
        Assert.Equal(0, harness.Net("bff.requests.active"));

        var span = Assert.Single(stopped, s => (string?)s.GetTagItem(PortaActivitySource.Tags.Component) == "request");
        Assert.Equal(PortaActivitySource.Activities.PortaRequest, span.OperationName);
        Assert.Equal("/echo/{id}", span.GetTagItem(PortaActivitySource.Tags.HttpRoute));
        Assert.Equal(200, span.GetTagItem(PortaActivitySource.Tags.HttpStatusCode));
    }

    [Theory]
    [InlineData("PURGE")] // nonstandard but token-valid; Kestrel accepts it
    [InlineData("get")] // methods are case-sensitive (RFC 9110); lowercase is not the standard verb
    public async Task NonStandardMethod_CollapsesTo_OTHER(string method)
    {
        using var harness = RecordingMetricsHarness.Create();
        var stopped = new System.Collections.Concurrent.ConcurrentBag<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == PortaActivitySource.Source.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = stopped.Add,
        };
        ActivitySource.AddActivityListener(listener);

        using var host = await CreateHostAsync(harness.Metrics, enableTelemetry: true);
        var client = host.GetTestServer().CreateClient();

        using var request = new HttpRequestMessage(new HttpMethod(method), "/echo/42")
        {
            Content = new StringContent("request-body", Encoding.UTF8),
        };
        await client.SendAsync(request, TestContext.Current.CancellationToken);

        var duration = Assert.Single(harness.Drain("bff.request.duration"));
        Assert.Equal("_OTHER", duration.Tags["method"]);

        var reqSize = Assert.Single(harness.Drain("bff.request.size"));
        Assert.Equal("_OTHER", reqSize.Tags["method"]);

        var span = Assert.Single(stopped, s => (string?)s.GetTagItem(PortaActivitySource.Tags.Component) == "request");
        Assert.Equal("_OTHER", span.GetTagItem(PortaActivitySource.Tags.HttpMethod));
    }

    [Fact]
    public async Task TelemetryDisabled_RecordsNothing()
    {
        using var harness = RecordingMetricsHarness.Create();
        using var host = await CreateHostAsync(harness.Metrics, enableTelemetry: false);
        var client = host.GetTestServer().CreateClient();

        var response = await client.PostAsync(
            "/echo/7",
            new StringContent("x", Encoding.UTF8),
            TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Empty(harness.Drain("bff.request.duration"));
        Assert.Equal(0, harness.Net("bff.requests.active"));
    }

    private static Task<IHost> CreateHostAsync(PortaMetrics metrics, bool enableTelemetry)
    {
        var hostBuilder = new HostBuilder().ConfigureWebHost(webHost =>
        {
            webHost.UseTestServer();
            webHost.ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddSingleton(metrics);
                services.AddSingleton(Options.Create(new PortaCoreOptions { EnableTelemetry = enableTelemetry }));
            });
            webHost.Configure(app =>
            {
                app.UsePortaTelemetry();
                app.UseRouting();
                app.UseEndpoints(endpoints =>
                    endpoints.MapPost("/echo/{id}", async context =>
                    {
                        await context.Response.WriteAsync("response-body", context.RequestAborted);
                    }));
            });
        });

        return hostBuilder.StartAsync();
    }
}
