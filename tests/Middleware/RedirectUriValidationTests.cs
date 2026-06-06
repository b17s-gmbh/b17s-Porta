using b17s.Porta.Middleware;

namespace b17s.Porta.Tests.Middleware;

public class RedirectUriValidationTests
{
    [Theory]
    [InlineData("localhost")]
    [InlineData("LOCALHOST")]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.2")]
    [InlineData("::1")]
    [InlineData("[::1]")]
    [InlineData("[::1]%eth0")]
    [InlineData("::1%eth0")]
    public void IsLocalhost_ReturnsTrueForLoopback(string host)
    {
        Assert.True(RedirectUriValidation.IsLocalhost(host));
    }

    [Theory]
    [InlineData("evil.com")]
    [InlineData("8.8.8.8")]
    [InlineData("[2001:db8::1]")]
    [InlineData("2001:db8::1")]
    [InlineData("")]
    [InlineData("[]")]
    public void IsLocalhost_ReturnsFalseForNonLoopback(string host)
    {
        Assert.False(RedirectUriValidation.IsLocalhost(host));
    }

    [Theory]
    [InlineData("https://[::1]/dashboard")]
    [InlineData("https://[::1]:5001/dashboard")]
    [InlineData("http://[::1]/dashboard")]
    public void IsLocalhost_MatchesUriHostForIPv6(string absoluteUri)
    {
        var uri = new Uri(absoluteUri);
        Assert.True(RedirectUriValidation.IsLocalhost(uri.Host));
    }

    // Port-aware allow-list: a bare host entry matches any port, but a host:port
    // entry pins the port so that a hijacked sidecar on a different port cannot
    // be a redirect target.
    [Theory]
    [InlineData("https://app.example.com/", "app.example.com", true)]
    [InlineData("https://app.example.com:8443/", "app.example.com", true)]
    [InlineData("https://app.example.com:8443/", "app.example.com:8443", true)]
    [InlineData("https://app.example.com:8444/", "app.example.com:8443", false)]
    [InlineData("https://app.example.com/", "app.example.com:443", false)]
    public void MatchesAllowedHost_RespectsPort(string requestUri, string allowEntry, bool expected)
    {
        var parsed = new Uri(requestUri);
        Assert.Equal(expected, RedirectUriValidation.MatchesAllowedHost(parsed, [allowEntry]));
    }

    // IDN normalization: a punycode allow-list entry must match a unicode
    // request host (and vice versa). The .NET HttpRequest pipeline can deliver
    // either form depending on intermediary handling.
    [Theory]
    [InlineData("https://xn--mller-kva.example/", "müller.example")]
    [InlineData("https://müller.example/", "xn--mller-kva.example")]
    [InlineData("https://APP.EXAMPLE.COM/", "app.example.com")]
    [InlineData("https://app.example.com./", "app.example.com")]
    public void MatchesAllowedHost_IsIdnAndCaseInsensitive(string requestUri, string allowEntry)
    {
        var parsed = new Uri(requestUri);
        Assert.True(RedirectUriValidation.MatchesAllowedHost(parsed, [allowEntry]));
    }

    [Theory]
    [InlineData("/dashboard")]
    [InlineData("/")]
    [InlineData("/path/to/page?next=%2F%2Fok")] // encoded separators in a later segment/query are same-origin
    [InlineData("/foo%2Fbar")]
    public void IsSafeRelativeUri_AcceptsSameOriginRelativePaths(string uri)
    {
        Assert.True(RedirectUriValidation.IsSafeRelativeUri(uri));
    }

    // Literal and percent-encoded protocol-relative / backslash variants must be
    // rejected: once unescaped downstream they resolve to an external origin.
    [Theory]
    [InlineData("//evil.com")]
    [InlineData("/\\evil.com")]
    [InlineData("/%2F%2Fevil.com")]
    [InlineData("/%2Fevil.com")]
    [InlineData("/%5Cevil.com")]
    [InlineData("/%5cevil.com")]
    [InlineData("relative-without-leading-slash")]
    public void IsSafeRelativeUri_RejectsExternalOriginVariants(string uri)
    {
        Assert.False(RedirectUriValidation.IsSafeRelativeUri(uri));
    }

    // AllowLocalhost defaults to false now. The configured-redirect validator
    // must reject a loopback target unless the operator explicitly opts in.
    [Fact]
    public void ValidateConfiguredRedirectUri_LoopbackRejected_WhenAllowLocalhostFalse()
    {
        var failure = RedirectUriValidation.ValidateConfiguredRedirectUri(
            "http://localhost:5001/welcome",
            allowedHosts: [],
            allowLocalhost: false);

        Assert.NotNull(failure);
    }

    [Fact]
    public void ValidateConfiguredRedirectUri_LoopbackAccepted_WhenAllowLocalhostTrue()
    {
        var failure = RedirectUriValidation.ValidateConfiguredRedirectUri(
            "http://localhost:5001/welcome",
            allowedHosts: [],
            allowLocalhost: true);

        Assert.Null(failure);
    }

    [Theory]
    // Absolute URIs: query and fragment carrying secrets must be dropped.
    [InlineData("https://app.example.com/cb?access_token=secret", "https://app.example.com/cb")]
    [InlineData("https://app.example.com/cb#access_token=secret", "https://app.example.com/cb")]
    [InlineData("https://app.example.com/cb?a=1#b=2", "https://app.example.com/cb")]
    [InlineData("https://app.example.com:8443/cb?token=x", "https://app.example.com:8443/cb")]
    [InlineData("https://app.example.com/cb", "https://app.example.com/cb")]
    // Relative / malformed values fall back to separator slicing.
    [InlineData("/dashboard?access_token=secret", "/dashboard")]
    [InlineData("/dashboard#access_token=secret", "/dashboard")]
    [InlineData("not a uri?token=secret", "not a uri")]
    [InlineData("/dashboard", "/dashboard")]
    public void StripQueryForLogging_RemovesQueryAndFragment(string input, string expected)
    {
        Assert.Equal(expected, RedirectUriValidation.StripQueryForLogging(input));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void StripQueryForLogging_PassesThroughEmpty(string? input)
    {
        Assert.Equal(input, RedirectUriValidation.StripQueryForLogging(input!));
    }
}
