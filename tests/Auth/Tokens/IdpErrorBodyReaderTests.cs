using System.Net;
using System.Text;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

namespace b17s.Porta.Tests.Auth.Tokens;

public sealed class IdpErrorBodyReaderTests
{
    private const string TruncationMarker = "…(truncated)";

    [Fact]
    public async Task ReadSafeAsync_LoggingDisabled_ReturnsRedactedWithoutReadingBody()
    {
        var response = Response("the IdP echoed a refresh_token here");

        var result = await IdpErrorBodyReader.ReadSafeAsync(
            response,
            new PortaCoreOptions { LogIdpErrorBodies = false },
            TestContext.Current.CancellationToken);

        Assert.Equal("(redacted)", result);
    }

    [Fact]
    public async Task ReadSafeAsync_BodyWithinCap_ReturnsBodyVerbatim()
    {
        var response = Response("short body");

        var result = await IdpErrorBodyReader.ReadSafeAsync(
            response,
            new PortaCoreOptions { LogIdpErrorBodies = true, IdpErrorBodyMaxBytes = 512 },
            TestContext.Current.CancellationToken);

        Assert.Equal("short body", result);
    }

    [Fact]
    public async Task ReadSafeAsync_TruncationIsByteBased_NotCharacterBased()
    {
        // Five Greek alphas: 5 UTF-16 chars but 10 UTF-8 bytes (2 bytes each).
        // A character-based cap of 4 would slice to content[..4] = 4 chars = 8 bytes,
        // exceeding the documented byte budget. A byte-based cap must keep <= 4 bytes.
        var response = Response(new string('α', 5));

        var result = await IdpErrorBodyReader.ReadSafeAsync(
            response,
            new PortaCoreOptions { LogIdpErrorBodies = true, IdpErrorBodyMaxBytes = 4 },
            TestContext.Current.CancellationToken);

        Assert.EndsWith(TruncationMarker, result);
        var payload = result[..^TruncationMarker.Length];
        Assert.True(
            Encoding.UTF8.GetByteCount(payload) <= 4,
            $"payload was {Encoding.UTF8.GetByteCount(payload)} bytes, expected <= 4");
    }

    [Fact]
    public async Task ReadSafeAsync_BodyFitsCapInCharsButExceedsInBytes_IsTruncated()
    {
        // 3 chars (€ = 3 bytes each = 9 bytes). A char-based cap of 4 sees 3 <= 4
        // and returns the body untruncated; a byte-based cap of 4 must truncate.
        var response = Response(new string('€', 3));

        var result = await IdpErrorBodyReader.ReadSafeAsync(
            response,
            new PortaCoreOptions { LogIdpErrorBodies = true, IdpErrorBodyMaxBytes = 4 },
            TestContext.Current.CancellationToken);

        Assert.EndsWith(TruncationMarker, result);
    }

    private static HttpResponseMessage Response(string body) =>
        new(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
}
