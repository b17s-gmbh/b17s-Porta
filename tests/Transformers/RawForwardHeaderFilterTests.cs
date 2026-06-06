using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

namespace b17s.Porta.Tests.Transformers;

public class RawForwardHeaderFilterTests
{
    private static RawForwardHeaderPassThrough Empty() => new();

    [Theory]
    [InlineData("Connection")]
    [InlineData("connection")]
    [InlineData("Keep-Alive")]
    [InlineData("Proxy-Authenticate")]
    [InlineData("Proxy-Authorization")]
    [InlineData("TE")]
    [InlineData("Trailer")]
    [InlineData("Transfer-Encoding")]
    [InlineData("Upgrade")]
    [InlineData("Host")]
    public void HopByHopHeaders_AreStripped(string header)
    {
        Assert.False(
            RawForwardHeaderFilter.ShouldForwardClientHeader(header, "backend.example.com", Empty()),
            $"Hop-by-hop header '{header}' must not be forwarded");
    }

    [Theory]
    [InlineData("Cookie")]
    [InlineData("cookie")]
    [InlineData("Set-Cookie")]
    [InlineData("Authorization")]
    [InlineData("authorization")]
    [InlineData("X-Forwarded-For")]
    [InlineData("X-Forwarded-Host")]
    [InlineData("X-Forwarded-Proto")]
    [InlineData("x-forwarded-anything")]
    public void SensitiveClientHeaders_AreStrippedByDefault(string header)
    {
        Assert.False(
            RawForwardHeaderFilter.ShouldForwardClientHeader(header, "backend.example.com", Empty()),
            $"Sensitive header '{header}' must be stripped when not on the allow-list");
    }

    [Theory]
    [InlineData("Accept")]
    [InlineData("Content-Type")]
    [InlineData("User-Agent")]
    [InlineData("X-Custom-Header")]
    [InlineData("X-Tenant-Id")]
    public void NonSensitiveHeaders_PassThrough(string header)
    {
        Assert.True(
            RawForwardHeaderFilter.ShouldForwardClientHeader(header, "backend.example.com", Empty()),
            $"Non-sensitive header '{header}' should be forwarded");
    }

    [Fact]
    public void AllowList_OptsHeaderInForAnyDestination_WhenNoHostScopeConfigured()
    {
        var passThrough = new RawForwardHeaderPassThrough();
        passThrough.AllowedHeaders.Add("Authorization");

        Assert.True(RawForwardHeaderFilter.ShouldForwardClientHeader("Authorization", "backend.example.com", passThrough));
        Assert.True(RawForwardHeaderFilter.ShouldForwardClientHeader("authorization", "another.example.com", passThrough));
    }

    [Fact]
    public void AllowList_HeaderNotListed_StaysStripped()
    {
        var passThrough = new RawForwardHeaderPassThrough();
        passThrough.AllowedHeaders.Add("Authorization");

        // Cookie is not opted in
        Assert.False(RawForwardHeaderFilter.ShouldForwardClientHeader("Cookie", "backend.example.com", passThrough));
        // X-Forwarded-* is not opted in
        Assert.False(RawForwardHeaderFilter.ShouldForwardClientHeader("X-Forwarded-For", "backend.example.com", passThrough));
    }

    [Fact]
    public void AllowList_WithDestinationHostScope_OnlyForwardsToListedHosts()
    {
        var passThrough = new RawForwardHeaderPassThrough();
        passThrough.AllowedHeaders.Add("Authorization");
        passThrough.AllowedDestinationHosts.Add("internal.example.com");

        Assert.True(RawForwardHeaderFilter.ShouldForwardClientHeader("Authorization", "internal.example.com", passThrough));
        Assert.False(RawForwardHeaderFilter.ShouldForwardClientHeader("Authorization", "external.example.com", passThrough));
        // Case-insensitive host comparison
        Assert.True(RawForwardHeaderFilter.ShouldForwardClientHeader("Authorization", "INTERNAL.example.com", passThrough));
    }

    [Fact]
    public void AllowList_WithDestinationHostScope_StripsWhenDestinationUnknown()
    {
        var passThrough = new RawForwardHeaderPassThrough();
        passThrough.AllowedHeaders.Add("Authorization");
        passThrough.AllowedDestinationHosts.Add("internal.example.com");

        Assert.False(RawForwardHeaderFilter.ShouldForwardClientHeader("Authorization", null, passThrough));
    }

    [Fact]
    public void HopByHopHeader_NeverForwarded_EvenIfOnAllowList()
    {
        var passThrough = new RawForwardHeaderPassThrough();
        passThrough.AllowedHeaders.Add("Connection");

        Assert.False(RawForwardHeaderFilter.ShouldForwardClientHeader("Connection", "backend.example.com", passThrough));
    }

    [Fact]
    public void IsSensitiveClientHeader_RecognizesAllSensitiveHeaders()
    {
        Assert.True(RawForwardHeaderFilter.IsSensitiveClientHeader("Cookie"));
        Assert.True(RawForwardHeaderFilter.IsSensitiveClientHeader("Set-Cookie"));
        Assert.True(RawForwardHeaderFilter.IsSensitiveClientHeader("Authorization"));
        Assert.True(RawForwardHeaderFilter.IsSensitiveClientHeader("X-Forwarded-For"));
        Assert.False(RawForwardHeaderFilter.IsSensitiveClientHeader("Accept"));
        Assert.False(RawForwardHeaderFilter.IsSensitiveClientHeader("User-Agent"));
    }

    [Theory]
    [InlineData("Set-Cookie")]
    [InlineData("set-cookie")]
    [InlineData("Strict-Transport-Security")]
    [InlineData("Content-Security-Policy")]
    [InlineData("Content-Security-Policy-Report-Only")]
    [InlineData("Server")]
    [InlineData("X-Powered-By")]
    [InlineData("x-powered-by")]
    public void SensitiveBackendResponseHeaders_AreStrippedByDefault(string header)
    {
        Assert.False(
            RawForwardHeaderFilter.ShouldForwardBackendResponseHeader(header, Empty()),
            $"Backend response header '{header}' must not leak to the client by default");
    }

    [Theory]
    [InlineData("Connection")]
    [InlineData("Transfer-Encoding")]
    [InlineData("Keep-Alive")]
    public void HopByHopBackendResponseHeaders_AreStripped(string header)
    {
        Assert.False(
            RawForwardHeaderFilter.ShouldForwardBackendResponseHeader(header, Empty()),
            $"Hop-by-hop response header '{header}' must not be forwarded to the client");
    }

    [Theory]
    [InlineData("Content-Type")]
    [InlineData("Content-Length")]
    [InlineData("Cache-Control")]
    [InlineData("ETag")]
    [InlineData("X-Custom-Header")]
    public void NonSensitiveBackendResponseHeaders_PassThrough(string header)
    {
        Assert.True(
            RawForwardHeaderFilter.ShouldForwardBackendResponseHeader(header, Empty()),
            $"Non-sensitive response header '{header}' should be forwarded to the client");
    }

    [Fact]
    public void ResponseAllowList_OptsSensitiveHeaderInForClient()
    {
        var passThrough = new RawForwardHeaderPassThrough();
        passThrough.AllowedResponseHeaders.Add("Set-Cookie");

        Assert.True(RawForwardHeaderFilter.ShouldForwardBackendResponseHeader("Set-Cookie", passThrough));
        Assert.True(RawForwardHeaderFilter.ShouldForwardBackendResponseHeader("set-cookie", passThrough));
        // Other sensitive headers stay stripped
        Assert.False(RawForwardHeaderFilter.ShouldForwardBackendResponseHeader("Server", passThrough));
    }

    [Fact]
    public void ResponseAllowList_DoesNotUnstickHopByHop()
    {
        var passThrough = new RawForwardHeaderPassThrough();
        passThrough.AllowedResponseHeaders.Add("Transfer-Encoding");

        Assert.False(RawForwardHeaderFilter.ShouldForwardBackendResponseHeader("Transfer-Encoding", passThrough));
    }

    [Fact]
    public void IsSensitiveBackendResponseHeader_RecognizesAllSensitiveHeaders()
    {
        Assert.True(RawForwardHeaderFilter.IsSensitiveBackendResponseHeader("Set-Cookie"));
        Assert.True(RawForwardHeaderFilter.IsSensitiveBackendResponseHeader("Strict-Transport-Security"));
        Assert.True(RawForwardHeaderFilter.IsSensitiveBackendResponseHeader("Content-Security-Policy"));
        Assert.True(RawForwardHeaderFilter.IsSensitiveBackendResponseHeader("Content-Security-Policy-Report-Only"));
        Assert.True(RawForwardHeaderFilter.IsSensitiveBackendResponseHeader("Server"));
        Assert.True(RawForwardHeaderFilter.IsSensitiveBackendResponseHeader("X-Powered-By"));
        Assert.False(RawForwardHeaderFilter.IsSensitiveBackendResponseHeader("Content-Type"));
        Assert.False(RawForwardHeaderFilter.IsSensitiveBackendResponseHeader("Cache-Control"));
    }
}
