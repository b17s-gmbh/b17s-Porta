using b17s.Porta.Configuration;

using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Configuration;

/// <summary>
/// Regression tests for the option validator that gates session-auth startup.
/// Covers required-field and range checks (Authority, ClientId, ClientSecret,
/// timeouts, key lifetime) plus the SameSite=None &rArr; SecurePolicy=Always
/// cross-field rule: browsers silently drop SameSite=None cookies that are not
/// Secure, and HTTP downgrade would expose the cookie if SecurePolicy were
/// SameAsRequest or None.
/// </summary>
public class SessionAuthenticationConfigurationValidatorTests
{
    private static SessionAuthenticationConfiguration ValidBaseline() => new()
    {
        Authority = "https://idp.example.com",
        ClientId = "bff",
        ClientSecret = "shh",
        SessionTimeoutInMin = 60,
        Cookie = new CookieSecurityConfiguration
        {
            SameSite = "Strict",
            SecurePolicy = "Always",
            ExpireTimeSpanMinutes = 60,
        },
    };

    private static ValidateOptionsResult Validate(SessionAuthenticationConfiguration options)
        => new SessionAuthenticationConfigurationValidator().Validate(name: null, options);

    [Fact]
    public void Baseline_SecureDefaults_IsValid()
    {
        var result = Validate(ValidBaseline());

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData("None")]
    [InlineData("SameAsRequest")]
    public void SameSiteNone_WithoutSecureAlways_Fails(string securePolicy)
    {
        var options = ValidBaseline();
        options.Cookie.SameSite = "None";
        options.Cookie.SecurePolicy = securePolicy;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("SameSite='None'", StringComparison.Ordinal)
                && f.Contains("SecurePolicy='Always'", StringComparison.Ordinal));
    }

    [Fact]
    public void SameSiteNone_WithSecureAlways_IsValid()
    {
        var options = ValidBaseline();
        options.Cookie.SameSite = "None";
        options.Cookie.SecurePolicy = "Always";

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData("Lax", "None")]
    [InlineData("Lax", "SameAsRequest")]
    [InlineData("Strict", "None")]
    [InlineData("Strict", "SameAsRequest")]
    public void NonNoneSameSite_DoesNotTriggerSecureAlwaysRule(string sameSite, string securePolicy)
    {
        // Lax/Strict cookies are not subject to the SameSite=None+Secure browser rule,
        // so the cross-field validator must not flag them. Operators can still choose
        // to require HTTPS via SecurePolicy=Always - but it is not enforced here.
        var options = ValidBaseline();
        options.Cookie.SameSite = sameSite;
        options.Cookie.SecurePolicy = securePolicy;

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Fact]
    public void InvalidSameSiteValue_DoesNotAlsoTriggerCrossFieldError()
    {
        // The cross-field check must only fire when both individual values are
        // well-formed; otherwise the user sees two errors for one mistake.
        var options = ValidBaseline();
        options.Cookie.SameSite = "bogus";
        options.Cookie.SecurePolicy = "None";

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("SameSite 'bogus'", StringComparison.Ordinal));
        Assert.DoesNotContain(
            result.Failures!,
            f => f.Contains("SameSite='None' requires", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void EnabledRetry_WithNonPositiveMaxRetryAttempts_Fails(int attempts)
    {
        // Polly rejects MaxRetryAttempts < 1 when the token pipeline is built,
        // which would otherwise surface as an OptionsValidationException on the
        // first token call instead of at startup.
        var options = ValidBaseline();
        options.Resilience.EnableRetry = true;
        options.Resilience.MaxRetryAttempts = attempts;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("Resilience.MaxRetryAttempts", StringComparison.Ordinal));
    }

    [Fact]
    public void DisabledRetry_IgnoresMaxRetryAttempts()
    {
        // With EnableRetry=false the attempt count is never applied, so a zero
        // value (a plausible way to express "no retries") must not fail startup.
        var options = ValidBaseline();
        options.Resilience.EnableRetry = false;
        options.Resilience.MaxRetryAttempts = 0;

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(6)]
    [InlineData(-1)]
    public void KeyLifetimeDaysBelowSeven_Fails(int days)
    {
        // KeyManagementOptions.NewKeyLifetime rejects lifetimes under one week, but
        // only deep inside Data Protection key management on the first
        // protect/unprotect - the validator surfaces it at boot instead.
        var options = ValidBaseline();
        options.DataProtection.KeyLifetimeDays = days;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("DataProtection.KeyLifetimeDays", StringComparison.Ordinal));
    }

    [Fact]
    public void KeyLifetimeDaysOfExactlySeven_IsValid()
    {
        var options = ValidBaseline();
        options.DataProtection.KeyLifetimeDays = 7;

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void MissingAuthority_Fails(string? authority)
    {
        var options = ValidBaseline();
        options.Authority = authority!;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("Authority is required", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("not a url")]
    [InlineData("idp.example.com")]
    [InlineData("ftp://idp.example.com")]
    public void MalformedAuthority_Fails(string authority)
    {
        // The malformed branch is distinct from the required branch: a present but
        // unparseable (or non-http) value must name the offending input so the
        // operator can spot the typo in config.
        var options = ValidBaseline();
        options.Authority = authority;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("absolute http(s) URL", StringComparison.Ordinal)
                && f.Contains($"'{authority}'", StringComparison.Ordinal));
    }

    [Fact]
    public void HttpAuthority_IsAccepted()
    {
        // Plain http is parseable and allowed here; requiring HTTPS is governed
        // separately by RequireHttpsMetadata, not by this validator.
        var options = ValidBaseline();
        options.Authority = "http://localhost:8080/realms/dev";

        var result = Validate(options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void MissingClientId_Fails(string? clientId)
    {
        var options = ValidBaseline();
        options.ClientId = clientId!;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("ClientId is required", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void MissingClientSecret_Fails(string? clientSecret)
    {
        var options = ValidBaseline();
        options.ClientSecret = clientSecret!;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("ClientSecret is required", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void NonPositiveSessionTimeout_Fails(int minutes)
    {
        var options = ValidBaseline();
        options.SessionTimeoutInMin = minutes;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("SessionTimeoutInMin must be > 0", StringComparison.Ordinal));
    }

    [Fact]
    public void NullCookie_Fails()
    {
        // The property is non-nullable with a default, but configuration binding
        // can still null it out - the validator must catch that instead of letting
        // cookie setup NRE later.
        var options = ValidBaseline();
        options.Cookie = null!;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("Cookie must be set", StringComparison.Ordinal));
    }

    [Fact]
    public void NullDataProtection_Fails()
    {
        var options = ValidBaseline();
        options.DataProtection = null!;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("DataProtection must be set", StringComparison.Ordinal));
    }

    [Fact]
    public void InvalidSecurePolicyValue_Fails()
    {
        var options = ValidBaseline();
        options.Cookie.SecurePolicy = "bogus";

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("SecurePolicy 'bogus'", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void NonPositiveCookieExpireTimeSpan_Fails(int minutes)
    {
        var options = ValidBaseline();
        options.Cookie.ExpireTimeSpanMinutes = minutes;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("Cookie.ExpireTimeSpanMinutes must be > 0", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0.0)]
    [InlineData(-1.0)]
    public void NonPositiveRequestTimeout_Fails(double seconds)
    {
        var options = ValidBaseline();
        options.Resilience.RequestTimeoutSeconds = seconds;

        var result = Validate(options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("Resilience.RequestTimeoutSeconds must be > 0", StringComparison.Ordinal));
    }

    [Fact]
    public void MultipleFailures_AreAllReported()
    {
        // The validator accumulates errors instead of failing fast so a fresh
        // (default-constructed) configuration surfaces every missing required
        // field in one startup exception.
        var result = Validate(new SessionAuthenticationConfiguration());

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("Authority is required", StringComparison.Ordinal));
        Assert.Contains(result.Failures!, f => f.Contains("ClientId is required", StringComparison.Ordinal));
        Assert.Contains(result.Failures!, f => f.Contains("ClientSecret is required", StringComparison.Ordinal));
    }

    [Fact]
    public void OidcAuthOptionsValidator_AppliesSameRule()
    {
        // OidcAuthOptionsValidator delegates to the base validator; this guards
        // against accidental divergence between the two registered validators.
        var options = new OidcAuthOptions
        {
            Authority = "https://idp.example.com",
            ClientId = "bff",
            ClientSecret = "shh",
            SessionTimeoutInMin = 60,
            Cookie = new CookieSecurityConfiguration
            {
                SameSite = "None",
                SecurePolicy = "SameAsRequest",
                ExpireTimeSpanMinutes = 60,
            },
        };

        var result = new OidcAuthOptionsValidator().Validate(name: null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Failures!,
            f => f.Contains("SameSite='None'", StringComparison.Ordinal));
    }
}
