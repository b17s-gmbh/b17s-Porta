using b17s.Porta.Transformers;

namespace b17s.Porta.Tests.Spec;

/// <summary>
/// Spec §10 / Regression #19 — RouteUrlInterpolator is a security boundary. Hostile route
/// values MUST NOT be able to alter scheme/authority or escape the static path prefix; benign
/// values are URL-encoded and substituted. Validation runs before any client query is appended.
/// </summary>
public class RouteUrlInterpolatorContractTests
{
    private static string Interpolate(string template, params (string Key, object? Value)[] values)
    {
        var dict = values.ToDictionary(v => v.Key, v => v.Value);
        return RouteUrlInterpolator.Interpolate(template, dict);
    }

    [Fact]
    public void Substitutes_BenignValue()
    {
        var result = Interpolate("https://api.internal/users/{id}", ("id", "42"));

        Assert.Equal("https://api.internal/users/42", result);
    }

    [Fact]
    public void UrlEncodes_SpecialCharacters()
    {
        // A space must be percent-encoded, not left raw, and must stay within the path.
        var result = Interpolate("https://api.internal/users/{name}", ("name", "a b"));

        var uri = new Uri(result);
        Assert.Equal("api.internal", uri.Host);
        Assert.DoesNotContain(' ', result);
    }

    [Theory]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("../admin")]
    [InlineData("x?y")]            // query injection
    [InlineData("x#frag")]         // fragment injection
    [InlineData("a\\b")]           // backslash
    [InlineData("..%2fadmin")]     // already-encoded traversal
    [InlineData("%2e%2e")]         // already-encoded dots
    public void Rejects_HostileValues(string hostile)
    {
        Assert.Throws<InvalidRouteValueException>(
            () => Interpolate("https://api.internal/users/{id}", ("id", hostile)));
    }

    [Fact]
    public void RawSeparatorInValue_MustBePercentEncoded()
    {
        // §10: "Each segment is Uri.EscapeDataString-encoded" — a raw '/' MUST become %2F so the
        // value cannot introduce a new path segment. (Spec-correct expectation; currently fails
        // because the implementation lets the raw '/' survive as a path separator.)
        var result = Interpolate("https://api.internal/users/{id}", ("id", "a/b"));

        Assert.Equal("https://api.internal/users/a%2Fb", result);
    }

    [Fact]
    public void HostNeverChanges_EvenForAuthorityLikeValue()
    {
        // "@evil.com" must be encoded so '@' cannot act as a userinfo/authority delimiter.
        // Either it is rejected, or the resolved host stays api.internal — never evil.com.
        try
        {
            var result = Interpolate("https://api.internal/users/{id}", ("id", "@evil.com"));
            var uri = new Uri(result);
            Assert.Equal("api.internal", uri.Host);
        }
        catch (InvalidRouteValueException)
        {
            // Rejecting outright also satisfies the contract.
        }
    }

    [Theory]
    [InlineData("https://backend.internal/anything/{**path}")]
    [InlineData("https://backend.internal/anything/{*path}")]
    public void CatchAll_PreservesNestedPathSeparators(string template)
    {
        // ASP.NET Core binds both {*path} and {**path} under the bare key "path". A catch-all
        // placeholder in the backend template is the subtree-proxy opt-in: the value's '/'
        // separators must survive so a nested request path maps to a nested backend path.
        var result = Interpolate(template, ("path", "my/nested/path"));

        Assert.Equal("https://backend.internal/anything/my/nested/path", result);
    }

    [Fact]
    public void CatchAll_EncodesEachSegment_ButKeepsSeparators()
    {
        // Slashes are preserved, but each segment is still EscapeDataString-encoded so a
        // segment can neither introduce a space nor pivot the authority via '@'.
        var result = Interpolate(
            "https://backend.internal/anything/{**path}", ("path", "a b/@evil.com"));

        Assert.Equal("https://backend.internal/anything/a%20b/%40evil.com", result);
        Assert.Equal("backend.internal", new Uri(result).Host);
    }

    [Fact]
    public void CatchAll_StillRejectsTraversal()
    {
        // The slash-preserving path must not become a traversal hole: "a/../../etc" would
        // canonicalize above the template prefix, so a '..' segment is rejected outright.
        Assert.Throws<InvalidRouteValueException>(
            () => Interpolate("https://backend.internal/anything/{**path}", ("path", "a/../../etc")));
    }

    [Fact]
    public void SingleSegmentPlaceholder_StillEncodesSlashes_WhenNotCatchAll()
    {
        // A bare {path} is NOT a catch-all opt-in: slashes stay encoded so the default posture
        // remains locked down even when the route value happens to contain separators.
        var result = Interpolate("https://backend.internal/anything/{path}", ("path", "my/nested"));

        Assert.Equal("https://backend.internal/anything/my%2Fnested", result);
    }
}
