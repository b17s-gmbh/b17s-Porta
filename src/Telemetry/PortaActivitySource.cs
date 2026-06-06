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
        public const string PortaRequest = "bff.request";
        public const string Transformation = "bff.transformation";
        public const string BackendCall = "bff.backend";
        public const string Authentication = "bff.authentication";
        public const string TokenExchange = "bff.token_exchange";
        public const string TokenRefresh = "bff.token_refresh";
        public const string HealthCheck = "bff.health_check";
        public const string SessionManagement = "bff.session";
    }

    /// <summary>
    /// Tag names
    /// </summary>
    public static class Tags
    {
        // General
        public const string ServiceName = "bff.service.name";
        public const string Component = "bff.component";

        // HTTP
        public const string HttpMethod = "http.method";
        public const string HttpUrl = "http.url";
        public const string HttpStatusCode = "http.status_code";
        public const string HttpRoute = "http.route";

        // Backend
        public const string BackendService = "bff.backend.service";
        public const string BackendProtocol = "bff.backend.protocol";
        public const string BackendEndpoint = "bff.backend.endpoint";
        public const string BackendOperation = "bff.backend.operation";

        // Transformation
        public const string TransformationStrategy = "bff.transformation.strategy";
        public const string TransformationRule = "bff.transformation.rule";

        // Authentication
        public const string AuthProvider = "bff.auth.provider";
        public const string AuthUserId = "bff.auth.user_id";
        public const string AuthTokenType = "bff.auth.token_type";

        // Health Check
        public const string HealthStatus = "bff.health.status";
        public const string HealthBackendCount = "bff.health.backend_count";

        // Session
        public const string SessionId = "bff.session.id";
        public const string SessionUserId = "bff.session.user_id";

        // Error
        // Note: stack traces are intentionally NOT exposed as a tag - they are high-cardinality
        // and inner-exception messages can contain PII. Use Activity.AddException(ex) instead,
        // which records the stack trace as event-scoped attributes per OpenTelemetry semantic conventions.
        public const string ErrorType = "error.type";
        public const string ErrorMessage = "error.message";
    }

    /// <summary>
    /// Event names
    /// </summary>
    public static class Events
    {
        public const string RequestReceived = "bff.request.received";
        public const string RequestCompleted = "bff.request.completed";
        public const string BackendCallStarted = "bff.backend.call_started";
        public const string BackendCallCompleted = "bff.backend.call_completed";
        public const string TransformationStarted = "bff.transformation.started";
        public const string TransformationCompleted = "bff.transformation.completed";
        public const string AuthenticationStarted = "bff.authentication.started";
        public const string AuthenticationCompleted = "bff.authentication.completed";
        public const string HealthCheckPerformed = "bff.health_check.performed";
        public const string ErrorOccurred = "bff.error.occurred";
    }
}
