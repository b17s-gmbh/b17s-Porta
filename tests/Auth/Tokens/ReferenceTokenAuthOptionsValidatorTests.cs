using b17s.Porta.Auth.Tokens;
using b17s.Porta.Tests.Fixtures;

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

    [Fact]
    public void PrivateKeyJwt_ZitadelKeyFile_IsValid_WithoutClientIdOrSecret()
    {
        // The client_id comes from the Zitadel key file, so neither ClientId nor ClientSecret is needed.
        using var key = TestSigningKey.Rsa();
        var options = ValidBaseline();
        options.PrivateKeyJwt.Key = key.ZitadelKeyFile();

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Fact]
    public void PrivateKeyJwt_PemFileWithClientId_IsValid()
    {
        using var key = TestSigningKey.Rsa();
        var options = ValidBaseline();
        options.ClientId = "okta-client";
        options.PrivateKeyJwt.KeyFile = key.WriteTempFile(key.Pkcs8Pem);

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Fact]
    public void PrivateKeyJwt_PemKeyWithoutClientId_Fails()
    {
        // Only a Zitadel key file carries its own client id.
        using var key = TestSigningKey.Rsa();
        var options = ValidBaseline();
        options.PrivateKeyJwt.Key = key.Pkcs8Pem;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("ReferenceTokenAuth.ClientId is required", StringComparison.Ordinal));
    }

    [Fact]
    public void PrivateKeyJwt_ZitadelKeyFile_MismatchedClientId_Fails()
    {
        using var key = TestSigningKey.Rsa();
        var options = ValidBaseline();
        options.PrivateKeyJwt.Key = key.ZitadelKeyFile(clientId: "my-api@project");
        options.ClientId = "other-client";

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("does not match the clientId", StringComparison.Ordinal));
    }

    [Fact]
    public void PrivateKeyJwt_WithClientSecret_Fails()
    {
        using var key = TestSigningKey.Rsa();
        var options = ValidBaseline();
        options.PrivateKeyJwt.Key = key.ZitadelKeyFile();
        options.ClientSecret = "secret";

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("ClientSecret must not be set", StringComparison.Ordinal));
    }

    [Fact]
    public void PrivateKeyJwt_MissingFile_Fails()
    {
        var options = ValidBaseline();
        options.PrivateKeyJwt.KeyFile = Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.json");

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("could not be read", StringComparison.Ordinal));
    }

    [Fact]
    public void PrivateKeyJwt_ZitadelServiceAccountKey_Fails()
    {
        // Zitadel also issues "serviceaccount" key files; those identify a machine user, not the app.
        using var key = TestSigningKey.Rsa();
        var options = ValidBaseline();
        options.PrivateKeyJwt.Key = key.ZitadelKeyFile(type: "serviceaccount");

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("\"type\": \"application\"", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""{"type":"application","keyId":"k","clientId":"c","key":"-----BEGIN RSA PRIVATE KEY-----\ngarbage\n-----END RSA PRIVATE KEY-----"}""")]
    [InlineData("""{"type":"application","keyId":"k","key":"x"}""")]
    public void PrivateKeyJwt_MalformedKey_Fails(string key)
    {
        var options = ValidBaseline();
        options.ClientId = "c";
        options.PrivateKeyJwt.Key = key;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("ReferenceTokenAuth.PrivateKeyJwt is invalid", StringComparison.Ordinal));
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
