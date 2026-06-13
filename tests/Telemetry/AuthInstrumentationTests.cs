using System.Diagnostics;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Tests.Telemetry;

[Collection(PortaActivitySourceCollection.Name)]
public sealed class AuthInstrumentationTests
{
    [Fact]
    public async Task Authenticated_RecordsSuccessAndDuration_WithShortProviderTag()
    {
        using var harness = RecordingMetricsHarness.Create();
        var provider = new StubAuthProvider(new AuthenticationContext
        {
            AccessToken = "tok",
            Scheme = "b17s.Porta.Auth.Providers.SessionAuthProvider"
        });

        var result = await AuthInstrumentation.ResolveAsync(provider, new DefaultHttpContext(), allowOptional: false, harness.Metrics, enableTelemetry: true);

        Assert.True(result.IsAuthenticated);
        var successes = harness.Drain("bff.auth.successes");
        Assert.Single(successes);
        Assert.Equal("SessionAuthProvider", successes[0].Tags["provider"]);
        Assert.Empty(harness.Drain("bff.auth.failures"));
        Assert.Single(harness.Drain("bff.auth.duration"));
    }

    [Fact]
    public async Task RequiredAuth_Unauthenticated_RecordsFailure()
    {
        using var harness = RecordingMetricsHarness.Create();
        var provider = new StubAuthProvider(AuthenticationContext.Unauthenticated());

        var result = await AuthInstrumentation.ResolveAsync(provider, new DefaultHttpContext(), allowOptional: false, harness.Metrics, enableTelemetry: true);

        Assert.False(result.IsAuthenticated);
        var failures = harness.Drain("bff.auth.failures");
        Assert.Single(failures);
        Assert.Equal("unauthenticated", failures[0].Tags["reason"]);
        Assert.Empty(harness.Drain("bff.auth.successes"));
    }

    [Fact]
    public async Task OptionalAuth_Unauthenticated_RecordsNeitherSuccessNorFailure()
    {
        // An AllowAnonymous endpoint that resolves to anonymous is a deliberate non-auth, not a
        // failure: only the duration is recorded, so failures aren't inflated by anonymous traffic.
        using var harness = RecordingMetricsHarness.Create();
        var provider = new StubAuthProvider(AuthenticationContext.Unauthenticated());

        await AuthInstrumentation.ResolveAsync(provider, new DefaultHttpContext(), allowOptional: true, harness.Metrics, enableTelemetry: true);

        Assert.Empty(harness.Drain("bff.auth.successes"));
        Assert.Empty(harness.Drain("bff.auth.failures"));
        Assert.Single(harness.Drain("bff.auth.duration"));
    }

    [Fact]
    public async Task EmitsFixedAuthenticationSpan()
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

        var provider = new StubAuthProvider(new AuthenticationContext { AccessToken = "tok", Scheme = "Custom" });
        await AuthInstrumentation.ResolveAsync(provider, new DefaultHttpContext(), allowOptional: false, harness.Metrics, enableTelemetry: true);

        var span = Assert.Single(stopped, s => (string?)s.GetTagItem(PortaActivitySource.Tags.Component) == "authentication");
        Assert.Equal(PortaActivitySource.Activities.Authentication, span.OperationName);
        Assert.Equal("Custom", span.GetTagItem(PortaActivitySource.Tags.AuthProvider));
    }

    private sealed class StubAuthProvider(AuthenticationContext context) : IAuthenticationProvider
    {
        public Task<AuthenticationContext> GetAuthContextAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
            => Task.FromResult(context);
        public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
            => Task.FromResult<AuthenticationContext?>(null);
        public Task InvalidateAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
