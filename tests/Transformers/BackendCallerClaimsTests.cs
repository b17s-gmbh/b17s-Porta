using System.Net;
using System.Security.Claims;
using System.Text;

using b17s.Porta.Configuration;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// <see cref="BackendAuthContext.Claims"/> is part of the custom-handler contract: it must carry
/// the authenticated user's claims (first value wins for repeated claim types) and stay empty for
/// anonymous requests or hosts that never registered <see cref="IHttpContextAccessor"/>.
/// </summary>
public sealed class BackendCallerClaimsTests
{
    [Fact]
    public async Task AuthenticatedUser_ClaimsArePopulated_FirstValueWinsForRepeatedTypes()
    {
        var identity = new ClaimsIdentity(
            [
                new Claim("sub", "user-1"),
                new Claim("role", "admin"),
                new Claim("role", "auditor"),
            ],
            authenticationType: "test");
        var capture = new CapturingAuthHandler();

        var caller = CreateCaller(capture, new ClaimsPrincipal(identity));
        var result = await caller.CallAsync(
            new BackendRequest { Method = "GET", Url = "https://backend.test/data", BackendAuthPolicy = capture.PolicyName },
            TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.NotNull(capture.LastContext);
        Assert.Equal("user-1", capture.LastContext!.Claims["sub"]);
        Assert.Equal("admin", capture.LastContext.Claims["role"]);
    }

    [Fact]
    public async Task AnonymousUser_ClaimsAreEmpty()
    {
        var capture = new CapturingAuthHandler();

        var caller = CreateCaller(capture, new ClaimsPrincipal(new ClaimsIdentity()));
        var result = await caller.CallAsync(
            new BackendRequest { Method = "GET", Url = "https://backend.test/data", BackendAuthPolicy = capture.PolicyName },
            TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.NotNull(capture.LastContext);
        Assert.Empty(capture.LastContext!.Claims);
    }

    [Fact]
    public async Task NoHttpContextAccessor_ClaimsAreEmpty()
    {
        var capture = new CapturingAuthHandler();

        var caller = CreateCaller(capture, user: null);
        var result = await caller.CallAsync(
            new BackendRequest { Method = "GET", Url = "https://backend.test/data", BackendAuthPolicy = capture.PolicyName },
            TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.NotNull(capture.LastContext);
        Assert.Empty(capture.LastContext!.Claims);
    }

    private static BackendCaller CreateCaller(IBackendAuthHandler authHandler, ClaimsPrincipal? user)
    {
        var registry = new BackendAuthHandlerRegistry();
        registry.Register(authHandler);

        IHttpContextAccessor? accessor = null;
        if (user is not null)
        {
            accessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = user } };
        }

        return new BackendCaller(
            new SingleHandlerHttpClientFactory(new OkHandler()),
            registry,
            new ContentSerializer(),
            metrics: null,
            logger: NullLogger<BackendCaller>.Instance,
            coreOptions: Options.Create(new PortaCoreOptions()),
            httpContextAccessor: accessor);
    }

    private sealed class CapturingAuthHandler : IBackendAuthHandler
    {
        public BackendAuthContext? LastContext { get; private set; }

        public string PolicyName => "ClaimsCapture";

        public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
        {
            LastContext = context;
            return Task.CompletedTask;
        }
    }

    private sealed class SingleHandlerHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class OkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            });
    }
}
