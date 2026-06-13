using System.Net;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Spec §9 marks the raw-forward response DoS caps as MUST: a hostile/broken backend must not be
/// able to stream unbounded bytes (egress amplification → 502 "Backend response too large") or
/// dribble/stall a connection to pin a worker (slow-loris → 504 "Backend response stalled").
/// These are end-to-end <see cref="TestServer"/> tests that drive the real
/// <see cref="BackendCaller"/> against a fake backend producing an over-large / stalled response
/// stream, with deliberately small caps configured.
/// </summary>
public sealed class RawForwardResponseCapE2ETests
{
    [Fact]
    public async Task OverLargeResponse_Aborts_With502()
    {
        // Backend returns 64 KiB; the cap is 1 KiB, so the bounded copy must abort before the
        // body starts streaming and surface a 502 - never a truncated-but-"complete" body.
        using var bff = await CreateBffAsync(
            new OversizedBackendHandler(payloadBytes: 64 * 1024),
            configure: o =>
            {
                o.MaxRawForwardResponseBytes = 1024;
                o.RawForwardReadIdleTimeout = TimeSpan.Zero; // idle cap disabled - isolate the size cap
            });
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/raw/big", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("Backend response too large", body);
    }

    [Fact]
    public async Task StalledResponse_Aborts_With504()
    {
        // Backend sends headers (200) then never produces a body byte. The per-read idle timeout
        // (200 ms) must fire and surface a 504 rather than pinning the worker indefinitely.
        using var bff = await CreateBffAsync(
            new StalledBackendHandler(),
            configure: o =>
            {
                o.MaxRawForwardResponseBytes = 0; // size cap disabled - isolate the idle cap
                o.RawForwardReadIdleTimeout = TimeSpan.FromMilliseconds(200);
            });
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/raw/stall", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.GatewayTimeout, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("Backend response stalled", body);
    }

    private static async Task<IHost> CreateBffAsync(HttpMessageHandler backendHandler, Action<PortaCoreOptions> configure)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddPortaCore(o =>
                    {
                        o.RequireAuthorizationByDefault = false;
                        configure(o);
                    });
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddSingleton<PassThroughRawTransformer>();

                    // Point the BFF's outbound backend client at the fake backend handler.
                    services.AddHttpClient(BackendCaller.HttpClientName)
                        .ConfigurePrimaryHttpMessageHandler(() => backendHandler);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapRawForward<PassThroughRawTransformer>()
                            .FromGet("/raw/{*rest}")
                            .ToBackend("GET", "https://backend.test/data")
                            .AllowAnonymous()
                            .Build();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    private sealed class PassThroughRawTransformer : IRawTransformer
    {
    }

    /// <summary>Returns a 200 with a body larger than the configured cap.</summary>
    private sealed class OversizedBackendHandler(int payloadBytes) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[payloadBytes])
            });
    }

    /// <summary>Returns a 200 whose body never yields a byte, simulating a stalled backend.</summary>
    private sealed class StalledBackendHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new StallingStream())
            });
    }

    /// <summary>A read stream that blocks forever on the first read until cancelled.</summary>
    private sealed class StallingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => 0; set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class AnonymousAuthProvider : IAuthenticationProvider
    {
        public Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(AuthenticationContext.Unauthenticated());

        public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
            => Task.FromResult<AuthenticationContext?>(null);

        public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
