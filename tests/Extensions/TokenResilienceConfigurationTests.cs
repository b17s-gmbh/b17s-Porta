using System.Net;

using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;

using Polly;
using Polly.CircuitBreaker;
using Polly.Retry;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// Locks in that the <see cref="TokenRefreshResilienceConfiguration"/> opt-out
/// flags actually neutralize the corresponding strategy on the standard
/// resilience pipeline. <c>AddStandardResilienceHandler</c> always installs
/// retry + circuit breaker, so <c>EnableRetry=false</c> / <c>EnableCircuitBreaker=false</c>
/// must disable them explicitly rather than silently leaving package defaults active.
/// </summary>
public class TokenResilienceConfigurationTests
{
    [Fact]
    public void EnabledRetry_AppliesConfiguredAttempts()
    {
        var options = new HttpStandardResilienceOptions();
        var resilience = new TokenRefreshResilienceConfiguration
        {
            EnableRetry = true,
            MaxRetryAttempts = 5,
            InitialDelaySeconds = 2.0,
            UseJitter = false,
        };

        AuthenticationServiceExtensions.ConfigureTokenResilience(options, resilience);

        Assert.Equal(5, options.Retry.MaxRetryAttempts);
        Assert.Equal(TimeSpan.FromSeconds(2.0), options.Retry.Delay);
        Assert.False(options.Retry.UseJitter);
    }

    [Fact]
    public async Task DisabledRetry_NeverRetriesTransientFailures()
    {
        var options = new HttpStandardResilienceOptions();
        var resilience = new TokenRefreshResilienceConfiguration { EnableRetry = false };

        AuthenticationServiceExtensions.ConfigureTokenResilience(options, resilience);

        // The opt-out must keep MaxRetryAttempts inside Polly's valid range
        // ([Range(1, ...)]): setting it to 0 fails options validation when the
        // pipeline is built, turning the documented opt-out into an
        // OptionsValidationException on the first token call. Disabling is
        // modelled like the circuit-breaker opt-out below: a predicate that
        // never treats any outcome as retryable.
        Assert.True(options.Retry.MaxRetryAttempts > 0);

        var context = ResilienceContextPool.Shared.Get(TestContext.Current.CancellationToken);
        try
        {
            var args = new RetryPredicateArguments<HttpResponseMessage>(
                context,
                Outcome.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)),
                attemptNumber: 0);

            Assert.False(await options.Retry.ShouldHandle(args));
        }
        finally
        {
            ResilienceContextPool.Shared.Return(context);
        }
    }

    [Fact]
    public async Task DisabledRetry_PipelineBuilds_AndSendsExactlyOnce()
    {
        // End-to-end repro: the resilience pipeline is built (and its options
        // validated) on the first request through the named client, so the
        // opt-out has to survive an actual send - asserting the configured
        // property values alone proves nothing.
        var handler = new CountingFailureHandler();
        var services = new ServiceCollection();
        services.AddHttpClient("token-resilience-test")
            .ConfigurePrimaryHttpMessageHandler(() => handler)
            .AddStandardResilienceHandler()
            .Configure(options => AuthenticationServiceExtensions.ConfigureTokenResilience(
                options,
                new TokenRefreshResilienceConfiguration { EnableRetry = false }));

        await using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<IHttpClientFactory>()
            .CreateClient("token-resilience-test");

        using var response = await client.GetAsync(
            new Uri("https://idp.test/token"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1, handler.Attempts);
    }

    private sealed class CountingFailureHandler : HttpMessageHandler
    {
        public int Attempts;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Attempts);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        }
    }

    [Fact]
    public void EnabledCircuitBreaker_AppliesConfiguredThresholds()
    {
        var options = new HttpStandardResilienceOptions();
        var resilience = new TokenRefreshResilienceConfiguration
        {
            EnableCircuitBreaker = true,
            CircuitBreakerFailureRatio = 0.25,
            CircuitBreakerSamplingDurationSeconds = 45.0,
            CircuitBreakerMinimumThroughput = 20,
            CircuitBreakerBreakDurationSeconds = 15.0,
        };

        AuthenticationServiceExtensions.ConfigureTokenResilience(options, resilience);

        Assert.Equal(0.25, options.CircuitBreaker.FailureRatio);
        Assert.Equal(TimeSpan.FromSeconds(45.0), options.CircuitBreaker.SamplingDuration);
        Assert.Equal(20, options.CircuitBreaker.MinimumThroughput);
        Assert.Equal(TimeSpan.FromSeconds(15.0), options.CircuitBreaker.BreakDuration);
    }

    [Fact]
    public async Task DisabledCircuitBreaker_NeverTripsOnFailures()
    {
        var options = new HttpStandardResilienceOptions();
        var resilience = new TokenRefreshResilienceConfiguration { EnableCircuitBreaker = false };

        AuthenticationServiceExtensions.ConfigureTokenResilience(options, resilience);

        // A disabled circuit breaker is modelled as a predicate that never treats
        // any outcome as a failure, so even a server-error response is "not handled"
        // and the circuit stays closed.
        var context = ResilienceContextPool.Shared.Get(TestContext.Current.CancellationToken);
        try
        {
            var args = new CircuitBreakerPredicateArguments<HttpResponseMessage>(
                context,
                Outcome.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError)));

            var shouldHandle = await options.CircuitBreaker.ShouldHandle(args);

            Assert.False(shouldHandle);
        }
        finally
        {
            ResilienceContextPool.Shared.Return(context);
        }
    }
}
