using b17s.Porta.Configuration;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Transformers;

public class TrustedHostValidatorTests
{
    private static TrustedHostValidator Build(params string[] trustedHosts)
    {
        var options = Options.Create(new PortaCoreOptions { TrustedHosts = [.. trustedHosts] });
        return new TrustedHostValidator(options, NullLogger<TrustedHostValidator>.Instance);
    }

    [Fact]
    public void ValidateUrl_LiteralHost_OnTrustedList_Passes()
    {
        var validator = Build("https://api.example.com");

        validator.ValidateUrl("https://api.example.com/users", "ep");
    }

    [Fact]
    public void ValidateUrl_PathPlaceholder_StillValidatesAuthority()
    {
        var validator = Build("https://api.example.com");

        validator.ValidateUrl("https://api.example.com/users/{userId}", "ep");
    }

    [Theory]
    [InlineData("http://{host}/api")]
    [InlineData("https://{tenant}.example.com/api")]
    [InlineData("https://api.example.com:{port}/api")]
    [InlineData("{scheme}://api.example.com/api")]
    public void ValidateUrl_PlaceholderInAuthority_Throws(string url)
    {
        var validator = Build("https://api.example.com");

        var ex = Assert.Throws<InvalidOperationException>(() => validator.ValidateUrl(url, "ep"));
        Assert.Contains("placeholder", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateUrl_PlaceholderInAuthority_ThrowsEvenIfLiteralSubstringMatchesPattern()
    {
        // Without the authority-placeholder check, `{host}` would be compared as a literal
        // substring against the trusted-host regex and could match a permissive pattern.
        var validator = Build("*");

        Assert.Throws<InvalidOperationException>(() => validator.ValidateUrl("http://{host}/api", "ep"));
    }

    [Fact]
    public void ValidateUrl_UntrustedLiteralHost_Throws()
    {
        var validator = Build("https://api.example.com");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            validator.ValidateUrl("https://evil.example.org/api", "ep"));
        Assert.Contains("not in the trusted hosts list", ex.Message);
    }

    // P0-7 regression: `*.example.com` must match a single subdomain label only.
    // The earlier implementation used `[^/]+` which also matched dots, so a pattern
    // like `*.example.com` would accept `evil.attacker.com.example.com` or
    // `a.b.example.com`. The fix uses `[^./]+`.

    [Theory]
    [InlineData("https://api.example.com")]
    [InlineData("https://www.example.com")]
    public void ValidateUrl_Wildcard_MatchesSingleLabel(string url)
    {
        var validator = Build("*.example.com");

        validator.ValidateUrl(url, "ep");
    }

    [Theory]
    [InlineData("https://a.b.example.com/users")]
    [InlineData("https://evil.attacker.com.example.com/users")]
    [InlineData("https://api.internal.example.com/users")]
    public void ValidateUrl_Wildcard_DoesNotMatchAcrossDots(string url)
    {
        var validator = Build("*.example.com");

        var ex = Assert.Throws<InvalidOperationException>(() => validator.ValidateUrl(url, "ep"));
        Assert.Contains("not in the trusted hosts list", ex.Message);
    }

    [Fact]
    public void ValidateUrl_Wildcard_DoesNotMatchBareDomain()
    {
        // `*.example.com` should require at least one label - bare `example.com` must fail.
        var validator = Build("*.example.com");

        Assert.Throws<InvalidOperationException>(() => validator.ValidateUrl("https://example.com/api", "ep"));
    }

    [Fact]
    public void ValidateUrl_NoTrustedHostsConfigured_Throws()
    {
        var validator = Build();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            validator.ValidateUrl("https://api.example.com/users", "ep"));
        Assert.Contains("no trusted hosts are configured", ex.Message);
    }

    [Fact]
    public void IsTrusted_WithEmptyTrustList_ReturnsFalse()
    {
        var validator = Build();

        Assert.False(validator.IsTrusted("https://api.example.com"));
    }

    // Authority extraction must follow Uri canonicalization, not naive string-slicing.
    // A userinfo component (`user@host`) means the host is whatever follows the `@` -
    // here `evil.com`, not the trusted-looking `api.example.com` before it.

    [Fact]
    public void ValidateUrl_UserInfoSpoofsTrustedHost_Throws()
    {
        var validator = Build("https://api.example.com");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            validator.ValidateUrl("https://api.example.com@evil.com/api", "ep"));
        Assert.Contains("not in the trusted hosts list", ex.Message);
    }

    [Fact]
    public void IsTrusted_UserInfoSpoofsTrustedHost_ReturnsFalse()
    {
        var validator = Build("https://api.example.com");

        Assert.False(validator.IsTrusted("https://api.example.com@evil.com/api"));
    }

    [Fact]
    public void IsTrusted_UserInfoPrefix_DoesNotMatchCleanPattern()
    {
        // GetLeftPart(Authority) keeps the userinfo, so the compared authority is
        // `https://evil.com@api.example.com` - it does NOT match the userinfo-less
        // trusted pattern even though the real host is trusted. Fail closed: a URL
        // carrying embedded credentials must be added to the trust list verbatim.
        var validator = Build("https://api.example.com");

        Assert.False(validator.IsTrusted("https://evil.com@api.example.com/api"));
    }

    // Port pivot: a trusted host on an unexpected port is a different authority and must
    // not match a pattern that was registered without a port (default 443).

    [Fact]
    public void ValidateUrl_TrustedHostUnexpectedPort_Throws()
    {
        var validator = Build("https://api.example.com");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            validator.ValidateUrl("https://api.example.com:8443/api", "ep"));
        Assert.Contains("not in the trusted hosts list", ex.Message);
    }

    [Fact]
    public void ValidateUrl_TrustedHostExplicitDefaultPort_Passes()
    {
        // `:443` is the default for https, so Uri canonicalization drops it and the
        // authority still matches the port-less trusted pattern.
        var validator = Build("https://api.example.com");

        validator.ValidateUrl("https://api.example.com:443/api", "ep");
    }

    [Fact]
    public void IsTrusted_UnparseableUrl_ReturnsFalse()
    {
        // A URL that Uri cannot parse must fail closed rather than being reconstructed
        // by hand and compared against the patterns.
        var validator = Build("*");

        Assert.False(validator.IsTrusted("http://exa mple.com/api"));
    }
}
