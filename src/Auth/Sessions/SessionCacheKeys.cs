namespace b17s.Porta.Auth.Sessions;

/// <summary>
/// Cache-key construction for the session metadata record and the subject/email
/// revocation indexes maintained by <see cref="SessionManagementService"/>.
///
/// Shared with <see cref="DistributedCacheTicketStore"/>: the cookie handler's
/// sliding renewal only rewrites the auth ticket, so the ticket store slides
/// these entries' TTLs on every ticket write. Without that, the revocation
/// bookkeeping expires while the session is still alive and back-channel
/// logout by <c>sub</c> / admin terminate-by-email silently terminate nothing.
/// </summary>
internal static class SessionCacheKeys
{
    /// <summary>Per-session metadata record, keyed by the per-login session id.</summary>
    internal const string SessionMetadataPrefix = "porta:session_meta:";

    /// <summary>Subject (OIDC <c>sub</c> claim) → sessionIds index.</summary>
    internal const string SubjectIndexPrefix = "porta:sub_sessions:";

    /// <summary>Normalized (lowercase) email → sessionIds index.</summary>
    internal const string EmailIndexPrefix = "porta:email_sessions:";

    internal static string SessionMetadata(string sessionId) => SessionMetadataPrefix + sessionId;

    internal static string SubjectIndex(string subject) => SubjectIndexPrefix + subject;

    internal static string EmailIndex(string normalizedEmail) => EmailIndexPrefix + normalizedEmail;
}
