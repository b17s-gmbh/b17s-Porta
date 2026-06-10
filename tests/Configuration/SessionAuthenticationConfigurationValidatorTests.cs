using b17s.Porta.Configuration;

using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Configuration;

/// <summary>
/// Regression tests for the option validator that gates session-auth startup.
/// Covers the SameSite=None &rArr; SecurePolicy=Always cross-field rule: browsers
/// silently drop SameSite=None cookies that are not Secure, and HTTP downgrade
/// would expose the cookie if SecurePolicy were SameAsRequest or None.
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
