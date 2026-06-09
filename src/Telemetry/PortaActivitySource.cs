using System.Diagnostics;
using System.Reflection;

namespace b17s.Porta.Telemetry;

/// <summary>
/// Central ActivitySource for BFF telemetry and distributed tracing
/// </summary>
public static class PortaActivitySource
{
    /// <summary>
    /// Name of the BFF activity source
    /// </summary>
    public const string ActivitySourceName = "b17s.Porta";

    /// <summary>
    /// Version of the BFF library, derived at load time from the assembly's
    /// <see cref="AssemblyInformationalVersionAttribute"/> (e.g. "1.2.3+abc123"),
    /// falling back to <see cref="AssemblyFileVersionAttribute"/>, then "0.0.0".
    /// Always reflects the actual shipped build - no manual upkeep required.
    /// </summary>
    public static readonly string Version = ResolveAssemblyVersion();

    /// <summary>
    /// The ActivitySource instance for creating activities
    /// </summary>
    public static readonly ActivitySource Source = new(ActivitySourceName, Version);

    private static string ResolveAssemblyVersion()
    {
        var assembly = typeof(PortaActivitySource).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
        {
            // Strip the SourceLink "+commit" suffix so the tag stays low-cardinality
            // across rebuilds at the same SemVer.
            var plus = informational.IndexOf('+');
            return plus < 0 ? informational : informational[..plus];
        }

        var file = assembly.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version;
        return string.IsNullOrWhiteSpace(file) ? "0.0.0" : file;
    }

    /// <summary>
    /// Activity names
    /// </summary>
    public static class Activities
    {
        /// <summary>Span covering the handling of an inbound BFF request end-to-end.</summary>
        public const string PortaRequest = "bff.request";

        /// <summary>Span covering execution of a transformer (request/response transformation).</summary>
        public const string Transformation = "bff.transformation";

        /// <summary>Span covering a raw forward of a request to a backend without transformation.</summary>
        public const string RawForward = "bff.raw_forward";

        /// <summary>Span covering an outbound call to a backend service.</summary>
        public const string BackendCall = "bff.backend";

        /// <summary>Span covering authentication of an inbound request.</summary>
        public const string Authentication = "bff.authentication";

        /// <summary>Span covering an OAuth/OIDC token exchange.</summary>
        public const string TokenExchange = "bff.token_exchange";

        /// <summary>Span covering a token refresh operation.</summary>
        public const string TokenRefresh = "bff.token_refresh";

        /// <summary>Span covering a backend health check.</summary>
        public const string HealthCheck = "bff.health_check";

        /// <summary>Span covering a session management operation (create, invalidate, etc.).</summary>
        public const string SessionManagement = "bff.session";
    }

    /// <summary>
    /// Tag names
    /// </summary>
    public static class Tags
    {
        // General

        /// <summary>Tag for the name of the BFF service.</summary>
        public const string ServiceName = "bff.service.name";

        /// <summary>Tag for the BFF component that produced the span (e.g. transformer, middleware).</summary>
        public const string Component = "bff.component";

        // HTTP

        /// <summary>Tag for the HTTP request method (e.g. <c>GET</c>, <c>POST</c>).</summary>
        public const string HttpMethod = "http.method";

        /// <summary>Tag for the full HTTP request URL.</summary>
        public const string HttpUrl = "http.url";

        /// <summary>Tag for the HTTP response status code.</summary>
        public const string HttpStatusCode = "http.status_code";

        /// <summary>Tag for the low-cardinality HTTP route template (e.g. <c>/api/users/{id}</c>).</summary>
        public const string HttpRoute = "http.route";

        // Backend

        /// <summary>Tag for the name of the backend service being called.</summary>
        public const string BackendService = "bff.backend.service";

        /// <summary>Tag for the protocol used to reach the backend (e.g. http, grpc).</summary>
        public const string BackendProtocol = "bff.backend.protocol";

        /// <summary>Tag for the backend endpoint (URL or address) being called.</summary>
        public const string BackendEndpoint = "bff.backend.endpoint";

        /// <summary>Tag for the logical backend operation being invoked.</summary>
        public const string BackendOperation = "bff.backend.operation";

        // Transformation

        /// <summary>Tag for the transformation strategy applied.</summary>
        public const string TransformationStrategy = "bff.transformation.strategy";

        /// <summary>Tag for the specific transformation rule applied.</summary>
        public const string TransformationRule = "bff.transformation.rule";

        // Authentication

        /// <summary>Tag for the authentication provider that handled the request.</summary>
        public const string AuthProvider = "bff.auth.provider";

        /// <summary>Tag for the authenticated user's identifier.</summary>
        public const string AuthUserId = "bff.auth.user_id";

        /// <summary>Tag for the type of token used for authentication (e.g. bearer, reference).</summary>
        public const string AuthTokenType = "bff.auth.token_type";

        // Health Check

        /// <summary>Tag for the resulting health status of a health check.</summary>
        public const string HealthStatus = "bff.health.status";

        /// <summary>Tag for the number of backends evaluated during a health check.</summary>
        public const string HealthBackendCount = "bff.health.backend_count";

        // Session

        /// <summary>Tag for the session identifier.</summary>
        public const string SessionId = "bff.session.id";

        /// <summary>Tag for the user identifier associated with a session.</summary>
        public const string SessionUserId = "bff.session.user_id";

        // Error
        // Note: stack traces are intentionally NOT exposed as a tag - they are high-cardinality
        // and inner-exception messages can contain PII. Use Activity.AddException(ex) instead,
        // which records the stack trace as event-scoped attributes per OpenTelemetry semantic conventions.

        /// <summary>Tag for the type of error that occurred.</summary>
        public const string ErrorType = "error.type";

        /// <summary>Tag for the error message describing what occurred.</summary>
        public const string ErrorMessage = "error.message";
    }

    /// <summary>
    /// Event names
    /// </summary>
    public static class Events
    {
        /// <summary>Event marking that an inbound request was received.</summary>
        public const string RequestReceived = "bff.request.received";

        /// <summary>Event marking that request processing completed.</summary>
        public const string RequestCompleted = "bff.request.completed";

        /// <summary>Event marking that an outbound backend call started.</summary>
        public const string BackendCallStarted = "bff.backend.call_started";

        /// <summary>Event marking that an outbound backend call completed.</summary>
        public const string BackendCallCompleted = "bff.backend.call_completed";

        /// <summary>Event marking that a transformation started.</summary>
        public const string TransformationStarted = "bff.transformation.started";

        /// <summary>Event marking that a transformation completed.</summary>
        public const string TransformationCompleted = "bff.transformation.completed";

        /// <summary>Event marking that authentication started.</summary>
        public const string AuthenticationStarted = "bff.authentication.started";

        /// <summary>Event marking that authentication completed.</summary>
        public const string AuthenticationCompleted = "bff.authentication.completed";

        /// <summary>Event marking that a health check was performed.</summary>
        public const string HealthCheckPerformed = "bff.health_check.performed";

        /// <summary>Event marking that an error occurred during processing.</summary>
        public const string ErrorOccurred = "bff.error.occurred";
    }
}
