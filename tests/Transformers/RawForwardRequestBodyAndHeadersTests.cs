using System.Net;
using System.Text;

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
/// Regression tests for finding #7: raw-forward dropped inbound entity (content) headers
/// other than Content-Type, and only forwarded request bodies for POST/PUT/PATCH - so
/// DELETE/OPTIONS bodies were silently omitted.
/// </summary>
public sealed class RawForwardRequestBodyAndHeadersTests
{
    [Fact]
    public async Task RawForward_PreservesEntityContentHeaders()
    {
        // Content-Encoding / Content-Disposition are CONTENT headers - HttpRequestMessage.Headers
        // rejects them, so before the fix they were silently dropped and never reached the backend.
        var capture = new RequestCaptureHandler();
        using var bff = await CreateBffAsync(capture, builder => builder
            .FromPost("/proxy/upload")
            .ToBackend("POST", "https://backend.test/upload")
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var content = new ByteArrayContent("payload-bytes"u8.ToArray());
        content.Headers.TryAddWithoutValidation("Content-Type", "application/octet-stream");
        content.Headers.TryAddWithoutValidation("Content-Encoding", "gzip");
        content.Headers.TryAddWithoutValidation("Content-Disposition", "attachment; filename=\"f.bin\"");
        content.Headers.TryAddWithoutValidation("Content-Language", "en-US");

        var response = await client.PostAsync("/proxy/upload", content, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal("gzip", capture.LastContentEncoding);
        Assert.Equal("attachment; filename=\"f.bin\"", capture.LastContentDisposition);
        Assert.Equal("en-US", capture.LastContentLanguage);
        // Content-Type must still survive (it was the one header that worked before the fix).
        Assert.Equal("application/octet-stream", capture.LastContentType);
    }

    [Fact]
    public async Task RawForward_DeleteWithBody_ForwardsBody()
    {
        // Bulk-delete APIs legitimately send a body with DELETE. The old POST/PUT/PATCH
        // allowlist dropped it.
        var capture = new RequestCaptureHandler();
        using var bff = await CreateBffAsync(capture, builder => builder
            .FromDelete("/proxy/items")
            .ToBackend("DELETE", "https://backend.test/items")
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Delete, "/proxy/items")
        {
            Content = new StringContent("[1,2,3]", Encoding.UTF8, "application/json"),
        };
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal("[1,2,3]", capture.LastBody);
    }

    [Fact]
    public async Task RawForward_GetWithoutBody_SendsNoContent()
    {
        // Guard: the body-presence check must not attach an empty StreamContent to a
        // bodyless verb (the inbound Body stream is always "readable").
        var capture = new RequestCaptureHandler();
        using var bff = await CreateBffAsync(capture, builder => builder
            .FromGet("/proxy/items")
            .ToBackend("GET", "https://backend.test/items")
            .AllowAnonymous());
        var client = bff.GetTestServer().CreateClient();

        var response = await client.GetAsync("/proxy/items", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.False(capture.LastHadContent, "A bodyless GET must not forward request content");
    }

    private static async Task<IHost> CreateBffAsync(
        RequestCaptureHandler captureHandler,
        Action<RawForwardEndpointBuilder<DefaultRawForwardTransformer>> configure)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddPortaCore();
                    services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    services.AddScoped<DefaultRawForwardTransformer>();

                    // Intercept the BackendCaller's outbound requests so we can inspect the
                    // forwarded content headers and body without a real backend server.
                    services.AddHttpClient(BackendCaller.HttpClientName)
                        .ConfigurePrimaryHttpMessageHandler(() => captureHandler);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        var builder = endpoints.MapRawForward<DefaultRawForwardTransformer>();
                        configure(builder);
                        builder.Build();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    private sealed class RequestCaptureHandler : HttpMessageHandler
    {
        public bool LastHadContent { get; private set; }
        public string? LastBody { get; private set; }
        public string? LastContentType { get; private set; }
        public string? LastContentEncoding { get; private set; }
        public string? LastContentDisposition { get; private set; }
        public string? LastContentLanguage { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.Content != null)
            {
                LastHadContent = true;
                LastBody = await request.Content.ReadAsStringAsync(cancellationToken);
                var headers = request.Content.Headers;
                LastContentType = headers.ContentType?.MediaType;
                LastContentEncoding = headers.ContentEncoding.FirstOrDefault();
                LastContentDisposition = headers.ContentDisposition?.ToString();
                LastContentLanguage = headers.ContentLanguage.FirstOrDefault();
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true}", Encoding.UTF8, "application/json"),
            };
        }
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
