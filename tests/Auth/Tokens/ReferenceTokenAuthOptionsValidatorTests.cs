using b17s.Porta.Auth.Tokens;

using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Auth.Tokens;

/// <summary>
/// Regression tests for the startup validator on <see cref="ReferenceTokenAuthOptions"/>.
/// Without it, a missing Authority or an exhausted audience allow-list boots fine and
/// then rejects every request at introspection time - inconsistent with the OIDC
/// fail-at-boot posture.
/// </summary>
public class ReferenceTokenAuthOptionsValidatorTests
{
    private static ReferenceTokenAuthOptions ValidBaseline() => new()
    {
        Authority = "https://idp.example.com",
        ValidAudiences = ["api"],
    };

    private static ValidateOptionsResult Validate(ReferenceTokenAuthOptions options)
        => new ReferenceTokenAuthOptionsValidator().Validate(name: null, options);

    [Fact]
    public void Baseline_IsValid()
    {
        var result = Validate(ValidBaseline());

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void MissingAuthority_Fails(string authority)
    {
        var options = ValidBaseline();
        options.Authority = authority;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("Authority is required", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("not-a-url")]
    [InlineData("/relative/path")]
    [InlineData("ftp://idp.example.com")]
    public void MalformedAuthority_Fails(string authority)
    {
        var options = ValidBaseline();
        options.Authority = authority;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("absolute http(s) URL", StringComparison.Ordinal));
    }

    [Fact]
    public void EmptyTokenHeaderName_Fails()
    {
        // An empty header name never matches a request header, so every request
        // would silently fall through unauthenticated.
        var options = ValidBaseline();
        options.TokenHeaderName = "";

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("TokenHeaderName", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("client-id", "")]
    [InlineData("", "client-secret")]
    public void LoneIntrospectionCredential_Fails(string clientId, string clientSecret)
    {
        // ReferenceTokenService only attaches credentials when BOTH are set;
        // a lone value is silently ignored.
        var options = ValidBaseline();
        options.ClientId = clientId;
        options.ClientSecret = clientSecret;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("ClientId and ClientSecret must be configured together", StringComparison.Ordinal));
    }

    [Fact]
    public void BothIntrospectionCredentials_AreValid()
    {
        var options = ValidBaseline();
        options.ClientId = "client-id";
        options.ClientSecret = "client-secret";

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void NonPositiveDefaultCacheDuration_Fails(int minutes)
    {
        // The default duration is used as the distributed-cache entry lifetime when
        // the introspection response carries no exp; the cache rejects non-positive
        // lifetimes at request time.
        var options = ValidBaseline();
        options.DefaultCacheDuration = TimeSpan.FromMinutes(minutes);

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("DefaultCacheDuration", StringComparison.Ordinal));
    }

    [Fact]
    public void MaxCacheDurationBelowDefault_Fails()
    {
        var options = ValidBaseline();
        options.DefaultCacheDuration = TimeSpan.FromMinutes(10);
        options.MaxCacheDuration = TimeSpan.FromMinutes(5);

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("MaxCacheDuration", StringComparison.Ordinal));
    }

    [Fact]
    public void ValidateAudienceWithoutAnyAllowList_Fails()
    {
        // With audience validation on but no allow-list, ValidateBinding rejects
        // every token - the BFF boots fine and then 401s everything.
        var options = ValidBaseline();
        options.ValidAudiences = [];
        options.ValidClientIds = [];

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("ValidateAudience", StringComparison.Ordinal));
    }

    [Fact]
    public void ValidateAudienceWithClientIdAllowListOnly_IsValid()
    {
        var options = ValidBaseline();
        options.ValidAudiences = [];
        options.ValidClientIds = ["client-id"];

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Fact]
    public void ValidateAudienceDisabled_AllowsEmptyAllowLists()
    {
        var options = ValidBaseline();
        options.ValidateAudience = false;
        options.ValidAudiences = [];
        options.ValidClientIds = [];

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Fact]
    public void NegativeCacheDurationZero_IsValid()
    {
        // Zero is the documented way to disable negative caching.
        var options = ValidBaseline();
        options.NegativeCacheDuration = TimeSpan.Zero;

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }
}
