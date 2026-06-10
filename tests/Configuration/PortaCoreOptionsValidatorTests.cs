using b17s.Porta.Configuration;

using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Configuration;

/// <summary>
/// Regression tests for the startup validator on <see cref="PortaCoreOptions"/>.
/// Without it, invalid values surface as <see cref="ArgumentOutOfRangeException"/>
/// at the first backend call (HttpClient creation / resilience pipeline build)
/// instead of failing the host at boot.
/// </summary>
public class PortaCoreOptionsValidatorTests
{
    private static ValidateOptionsResult Validate(PortaCoreOptions options)
        => new PortaCoreOptionsValidator().Validate(name: null, options);

    [Fact]
    public void Defaults_AreValid()
    {
        var result = Validate(new PortaCoreOptions());

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-30)]
    public void NonPositiveDefaultTimeout_Fails(int seconds)
    {
        var options = new PortaCoreOptions { DefaultTimeout = TimeSpan.FromSeconds(seconds) };

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("DefaultTimeout", StringComparison.Ordinal));
    }

    [Fact]
    public void NegativeTokenRefreshSkew_Fails()
    {
        var options = new PortaCoreOptions { TokenRefreshSkew = TimeSpan.FromSeconds(-1) };

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("TokenRefreshSkew", StringComparison.Ordinal));
    }

    [Fact]
    public void ZeroTokenRefreshSkew_IsValid()
    {
        // Zero skew means "refresh only at actual expiry" - unusual but coherent.
        var options = new PortaCoreOptions { TokenRefreshSkew = TimeSpan.Zero };

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData(-1)] // unlimited
    [InlineData(0)]  // no body logs
    [InlineData(512)]
    public void DocumentedMaxBodyLogLengthValues_AreValid(int length)
    {
        var options = new PortaCoreOptions { MaxBodyLogLength = length };

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Fact]
    public void MaxBodyLogLengthBelowMinusOne_Fails()
    {
        var options = new PortaCoreOptions { MaxBodyLogLength = -2 };

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("MaxBodyLogLength", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MaxValue)] // would overflow the max+1 read buffer in IdpErrorBodyReader
    [InlineData(PortaCoreOptionsValidator.IdpErrorBodyMaxBytesCeiling + 1)]
    public void IdpErrorBodyMaxBytesOutOfRange_Fails(int bytes)
    {
        var options = new PortaCoreOptions { IdpErrorBodyMaxBytes = bytes };

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("IdpErrorBodyMaxBytes", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(PortaCoreOptionsValidator.IdpErrorBodyMaxBytesCeiling)]
    public void IdpErrorBodyMaxBytesBoundaryValues_AreValid(int bytes)
    {
        var options = new PortaCoreOptions { IdpErrorBodyMaxBytes = bytes };

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void MaxRetryAttemptsBelowOne_IsValid(int attempts)
    {
        // A ceiling below 1 is the documented way to disable retries app-wide;
        // ConfigureBackendResilience models it as a never-retry predicate instead
        // of handing the invalid count to Polly.
        var options = new PortaCoreOptions { MaxRetryAttempts = attempts };

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Fact]
    public void NonPositiveResponseByteCaps_AreValid()
    {
        // Non-positive values are the documented way to disable the caps.
        var options = new PortaCoreOptions
        {
            MaxBackendResponseBytes = 0,
            MaxRawForwardResponseBytes = -1,
            RawForwardReadIdleTimeout = TimeSpan.Zero,
        };

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }
}
