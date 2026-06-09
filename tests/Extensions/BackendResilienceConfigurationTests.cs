using System.Net;

using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

using Microsoft.Extensions.Http.Resilience;

using Polly;
using Polly.Retry;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// Locks in that the per-endpoint <c>WithRetries(n)</c> budget is actually honored by the backend
/// resilience pipeline. The standard handler bakes a single <c>MaxRetryAttempts</c>, so without the
/// <c>ShouldHandle</c> gate installed by <see cref="PortaServiceExtensions.ConfigureBackendResilience"/>
/// every endpoint retried the global count regardless of its <c>WithRetries(n)</c> argument
/// (the budget carried on <see cref="BackendCaller.RetryBudgetOption"/> was ignored).
/// </summary>
public class BackendResilienceConfigurationTests
{
    private static HttpStandardResilienceOptions Configure(int ceiling)
    {
        var options = new HttpStandardResilienceOptions();
        PortaServiceExtensions.ConfigureBackendResilience(
            options,
            new PortaCoreOptions { MaxRetryAttempts = ceiling });
        return options;
    }

    private static async Task<bool> ShouldRetryAsync(
        HttpStandardResilienceOptions options,
        int attemptNumber,
        int? budget,
        Outcome<HttpResponseMessage> outcome)
    {
        var context = ResilienceContextPool.Shared.Get(TestContext.Current.CancellationToken);
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test");
            if (budget.HasValue)
            {
                request.Options.Set(BackendCaller.RetryBudgetOption, budget.Value);
            }
            // The HttpClient resilience handler snapshots the outbound request onto the context;
            // replicate that here so the gate can read the budget the same way it does in production.
            context.SetRequestMessage(request);

            var args = new RetryPredicateArguments<HttpResponseMessage>(context, outcome, attemptNumber);
            return await options.Retry.ShouldHandle(args);
        }
        finally
        {
            ResilienceContextPool.Shared.Return(context);
        }
    }

    private static Outcome<HttpResponseMessage> Transient()
        => Outcome.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

    [Theory]
    // budget of 1 retry: retry the first failure (attempt 0), stop before the second.
    [InlineData(1, 0, true)]
    [InlineData(1, 1, false)]
    // budget of 3 retries: keep going through attempt 2, stop at attempt 3.
    [InlineData(3, 0, true)]
    [InlineData(3, 2, true)]
    [InlineData(3, 3, false)]
    // budget of 0: no retries at all.
    [InlineData(0, 0, false)]
    public async Task PerEndpointBudget_GatesRetries_WithinCeiling(int budget, int attemptNumber, bool expected)
    {
        // Ceiling well above the budget so the budget - not the ceiling - is what stops retries.
        var options = Configure(ceiling: 10);

        var shouldRetry = await ShouldRetryAsync(options, attemptNumber, budget, Transient());

        Assert.Equal(expected, shouldRetry);
    }

    [Fact]
    public async Task DistinctBudgets_ProduceDistinctRetryDecisions()
    {
        // Regression for the reported bug: WithRetries(1) and WithRetries(3) must NOT behave the same.
        var options = Configure(ceiling: 10);

        // At attempt index 1 (deciding the 2nd retry): budget 1 is spent, budget 3 still has room.
        Assert.False(await ShouldRetryAsync(options, attemptNumber: 1, budget: 1, Transient()));
        Assert.True(await ShouldRetryAsync(options, attemptNumber: 1, budget: 3, Transient()));
    }

    [Fact]
    public async Task BudgetAboveCeiling_IsClampedByMaxRetryAttempts()
    {
        // Ceiling 3, endpoint asks for 10. The clamp to the ceiling is enforced by the pipeline's own
        // MaxRetryAttempts (Polly stops invoking ShouldHandle once it is reached), so the effective
        // retry count is min(budget, ceiling) = 3. The gate itself only enforces the lower bound, so
        // while attempts remain below the ceiling it keeps deferring to the transient predicate.
        var options = Configure(ceiling: 3);

        Assert.Equal(3, options.Retry.MaxRetryAttempts);
        Assert.True(await ShouldRetryAsync(options, attemptNumber: 2, budget: 10, Transient()));
    }

    [Fact]
    public async Task MissingBudget_FallsBackToCeiling()
    {
        // Non-Porta callers sharing the client carry no budget; they get the app-wide ceiling.
        var options = Configure(ceiling: 2);

        Assert.True(await ShouldRetryAsync(options, attemptNumber: 1, budget: null, Transient()));
        Assert.False(await ShouldRetryAsync(options, attemptNumber: 2, budget: null, Transient()));
    }

    [Fact]
    public async Task BudgetIsHonoredOnExceptionOutcomes()
    {
        // Exception outcomes carry no response, so the budget must come from the resilience context.
        var options = Configure(ceiling: 10);
        var transientException = Outcome.FromException<HttpResponseMessage>(
            new HttpRequestException("connection reset"));

        Assert.True(await ShouldRetryAsync(options, attemptNumber: 0, budget: 2, transientException));
        Assert.False(await ShouldRetryAsync(options, attemptNumber: 2, budget: 2, transientException));
    }

    [Fact]
    public async Task NonTransientOutcome_IsNotRetried_EvenWithBudget()
    {
        // A successful response is not transient: the gate must defer to the standard predicate and
        // not retry just because budget remains.
        var options = Configure(ceiling: 10);
        var success = Outcome.FromResult(new HttpResponseMessage(HttpStatusCode.OK));

        Assert.False(await ShouldRetryAsync(options, attemptNumber: 0, budget: 5, success));
    }
}
