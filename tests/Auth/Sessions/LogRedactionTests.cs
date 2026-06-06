using b17s.Porta.Auth.Sessions;

namespace b17s.Porta.Tests.Auth.Sessions;

public class LogRedactionTests
{
    [Fact]
    public void RedactSessionId_DoesNotContainRawSessionId()
    {
        var sessionId = "a1b2c3d4e5f6000111222333444555666"; // shape of a Guid("N")

        var redacted = LogRedaction.RedactSessionId(sessionId);

        Assert.DoesNotContain(sessionId, redacted, StringComparison.Ordinal);
        Assert.StartsWith("sid:", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactSessionId_IsStableForTheSameInput()
    {
        const string sessionId = "session-123";

        Assert.Equal(LogRedaction.RedactSessionId(sessionId), LogRedaction.RedactSessionId(sessionId));
    }

    [Fact]
    public void RedactSessionId_DiffersForDifferentInputs()
    {
        Assert.NotEqual(LogRedaction.RedactSessionId("session-a"), LogRedaction.RedactSessionId("session-b"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void RedactSessionId_NullOrEmpty_ReturnsPlaceholder(string? sessionId)
    {
        Assert.Equal("(none)", LogRedaction.RedactSessionId(sessionId));
    }

    [Fact]
    public void FingerprintEmail_DoesNotContainRawEmail_AndIsPrefixed()
    {
        const string email = "alice@example.com";

        var fingerprint = LogRedaction.FingerprintEmail(email);

        Assert.DoesNotContain(email, fingerprint, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("email:", fingerprint, StringComparison.Ordinal);
    }

    [Fact]
    public void FingerprintEmail_IsCaseInsensitive()
    {
        Assert.Equal(
            LogRedaction.FingerprintEmail("Alice@Example.com"),
            LogRedaction.FingerprintEmail("alice@example.com"));
    }

    [Fact]
    public void FingerprintEmail_DiffersForDifferentAddresses()
    {
        Assert.NotEqual(
            LogRedaction.FingerprintEmail("alice@example.com"),
            LogRedaction.FingerprintEmail("bob@example.com"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void FingerprintEmail_NullOrEmpty_ReturnsPlaceholder(string? email)
    {
        Assert.Equal("(none)", LogRedaction.FingerprintEmail(email));
    }

    [Fact]
    public void FingerprintSubject_DoesNotContainRawSubject_AndIsPrefixed()
    {
        const string subject = "8f3b2c10-0000-4a11-9b22-aabbccddeeff";

        var fingerprint = LogRedaction.FingerprintSubject(subject);

        Assert.DoesNotContain(subject, fingerprint, StringComparison.Ordinal);
        Assert.StartsWith("sub:", fingerprint, StringComparison.Ordinal);
    }

    [Fact]
    public void FingerprintSubject_IsStableForTheSameInput()
    {
        const string subject = "subject-123";

        Assert.Equal(LogRedaction.FingerprintSubject(subject), LogRedaction.FingerprintSubject(subject));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void FingerprintSubject_NullOrEmpty_ReturnsPlaceholder(string? subject)
    {
        Assert.Equal("(none)", LogRedaction.FingerprintSubject(subject));
    }
}
