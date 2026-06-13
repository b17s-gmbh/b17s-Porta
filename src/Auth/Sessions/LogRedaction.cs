using System.Security.Cryptography;
using System.Text;

namespace b17s.Porta.Auth.Sessions;

/// <summary>
/// Redaction helpers for Secret-classified identifiers (session ids) that must not
/// appear verbatim in logs. A session id is both a credential-equivalent lookup key
/// (it addresses the server-side auth ticket holding the access/refresh/id tokens) and
/// a Secret per <c>SECURITY.md</c>, so the raw value must never reach the log stream.
/// </summary>
internal static class LogRedaction
{
    /// <summary>
    /// Returns a non-reversible <c>sid:{sha256-prefix}</c> fingerprint of a session id
    /// for use in log messages. The raw id is never emitted, but the fingerprint is
    /// stable, so operators can still correlate multiple log lines for the same session.
    /// Returns <c>(none)</c> for a null/empty id.
    /// </summary>
    public static string RedactSessionId(string? sessionId)
    {
        if (string.IsNullOrEmpty(sessionId))
        {
            return "(none)";
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(sessionId));
        return $"sid:{Convert.ToHexString(digest, 0, 6)}";
    }

    /// <summary>
    /// Returns a stable <c>email:{sha256-prefix}</c> fingerprint of an email address for
    /// log correlation. Unlike <see cref="RedactSessionId"/> the raw email is still logged
    /// alongside this (email is PII, not a Secret, and the raw value aids debugging); the
    /// fingerprint lets operators correlate across log lines and systems that only retain
    /// the hash. The address is lower-cased before hashing so the fingerprint is stable
    /// regardless of casing. Returns <c>(none)</c> for a null/empty address.
    /// </summary>
    public static string FingerprintEmail(string? email)
        => Fingerprint("email", email?.ToLowerInvariant());

    /// <summary>
    /// Returns a stable <c>sub:{sha256-prefix}</c> fingerprint of an OIDC subject (<c>sub</c>)
    /// claim for log correlation. Like <see cref="FingerprintEmail"/> the raw subject is still
    /// logged alongside this; the fingerprint matches the <c>sid</c> treatment so operators can
    /// correlate sessions. Returns <c>(none)</c> for a null/empty subject.
    /// </summary>
    public static string FingerprintSubject(string? subject)
        => Fingerprint("sub", subject);

    /// <summary>
    /// Returns a stable, non-reversible <c>{category}:{sha256-prefix}</c> token for use as a
    /// refresh-lock partition key. The hash is deterministic, so the same identifier maps to the
    /// same lock across replicas and connections (preserving the single-flight refresh guarantee).
    /// Hashing matters because the lock key is emitted verbatim in the lock-timeout log line: on
    /// the session-id fallback paths the identifier is credential-equivalent and per
    /// <c>SECURITY.md</c> must never reach the log stream. (The session email/subject index keys,
    /// by contrast, carry the raw identifier and do get logged - email and <c>sub</c> are PII,
    /// not Secrets, and are logged raw by design; see <see cref="FingerprintEmail"/>.) The
    /// <paramref name="category"/> (e.g. <c>user</c>, <c>bff-session</c>) is preserved in the
    /// clear so operators can still tell which identifier path produced the lock.
    /// </summary>
    public static string FingerprintLockComponent(string category, string? value)
        => Fingerprint(category, value);

    private static string Fingerprint(string prefix, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "(none)";
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return $"{prefix}:{Convert.ToHexString(digest, 0, 6)}";
    }
}
