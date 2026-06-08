using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.Extensions.Http.Resilience;

using Polly;
using Polly.CircuitBreaker;

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
    public void DisabledRetry_ZeroesOutRetryAttempts()
    {
        var options = new HttpStandardResilienceOptions();
        // Sanity: the standard pipeline ships with retries enabled by default,
        // so a non-zero default is what makes the opt-out meaningful.
        Assert.True(options.Retry.MaxRetryAttempts > 0);

        var resilience = new TokenRefreshResilienceConfiguration { EnableRetry = false };

        AuthenticationServiceExtensions.ConfigureTokenResilience(options, resilience);

        Assert.Equal(0, options.Retry.MaxRetryAttempts);
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
