using System.Text.Json;
using System.Text.Json.Serialization;

namespace b17s.Porta.Transformers;

/// <summary>
/// GraphQL request payload sent to backends.
/// </summary>
public sealed class GraphQLRequest
{
    /// <summary>
    /// The GraphQL query string.
    /// </summary>
    [JsonPropertyName("query")]
    public required string Query { get; init; }

    /// <summary>
    /// Optional operation name when the query contains multiple operations.
    /// </summary>
    [JsonPropertyName("operationName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? OperationName { get; init; }

    /// <summary>
    /// Optional variables for the query.
    /// </summary>
    [JsonPropertyName("variables")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Variables { get; init; }
}

/// <summary>
/// GraphQL response from backends.
/// </summary>
public sealed class GraphQLResponse
{
    /// <summary>
    /// The data payload (may be null if errors occurred).
    /// </summary>
    [JsonPropertyName("data")]
    public JsonElement? Data { get; init; }

    /// <summary>
    /// Array of GraphQL errors (may be null or empty on success).
    /// </summary>
    [JsonPropertyName("errors")]
    public List<GraphQLError>? Errors { get; init; }

    /// <summary>
    /// Optional extensions from the GraphQL server.
    /// </summary>
    [JsonPropertyName("extensions")]
    public JsonElement? Extensions { get; init; }
}

/// <summary>
/// GraphQL error object.
/// </summary>
public sealed class GraphQLError
{
    /// <summary>
    /// Error message.
    /// </summary>
    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    /// <summary>
    /// Source locations in the query where the error occurred.
    /// </summary>
    [JsonPropertyName("locations")]
    public List<GraphQLLocation>? Locations { get; init; }

    /// <summary>
    /// Path to the field that caused the error.
    /// </summary>
    [JsonPropertyName("path")]
    public List<JsonElement>? Path { get; init; }

    /// <summary>
    /// Additional error details (may contain 'code' for error classification).
    /// </summary>
    [JsonPropertyName("extensions")]
    public GraphQLErrorExtensions? Extensions { get; init; }
}

/// <summary>
/// Location in a GraphQL query where an error occurred.
/// </summary>
public sealed class GraphQLLocation
{
    [JsonPropertyName("line")]
    public int Line { get; init; }

    [JsonPropertyName("column")]
    public int Column { get; init; }
}

/// <summary>
/// Extension data for GraphQL errors.
/// </summary>
public sealed class GraphQLErrorExtensions
{
    /// <summary>
    /// Error code (e.g., "NOT_FOUND", "UNAUTHORIZED", "VALIDATION_ERROR").
    /// </summary>
    [JsonPropertyName("code")]
    public string? Code { get; init; }

    /// <summary>
    /// Additional properties from the extensions object.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalProperties { get; init; }
}

/// <summary>
/// Result of a GraphQL backend call.
/// </summary>
/// <typeparam name="T">The expected data type.</typeparam>
public readonly struct GraphQLResult<T>
{
    /// <summary>
    /// Whether the GraphQL call was successful (no errors and data extracted).
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// HTTP status code from the backend (usually 200 for GraphQL).
    /// </summary>
    public int HttpStatusCode { get; }

    /// <summary>
    /// Mapped status code based on GraphQL errors (e.g., 404 for NOT_FOUND).
    /// </summary>
    public int MappedStatusCode { get; }

    /// <summary>
    /// The extracted data from the GraphQL response.
    /// </summary>
    public T? Data { get; }

    /// <summary>
    /// Error message if the call failed.
    /// </summary>
    public string? Error { get; }

    /// <summary>
    /// Original GraphQL errors from the response.
    /// </summary>
    public IReadOnlyList<GraphQLError>? Errors { get; }

    /// <summary>
    /// Type of error for categorization.
    /// </summary>
    public BackendErrorType ErrorType { get; }

    private GraphQLResult(bool isSuccess, int httpStatusCode, int mappedStatusCode, T? data, string? error, IReadOnlyList<GraphQLError>? errors, BackendErrorType errorType)
    {
        IsSuccess = isSuccess;
        HttpStatusCode = httpStatusCode;
        MappedStatusCode = mappedStatusCode;
        Data = data;
        Error = error;
        Errors = errors;
        ErrorType = errorType;
    }

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    public static GraphQLResult<T> Success(T data, int httpStatusCode = 200) =>
        new(true, httpStatusCode, httpStatusCode, data, null, null, BackendErrorType.None);

    /// <summary>
    /// Creates a failure result from GraphQL errors.
    /// </summary>
    public static GraphQLResult<T> FromGraphQLErrors(IReadOnlyList<GraphQLError> errors, int httpStatusCode = 200)
    {
        var primaryError = errors.Count > 0 ? errors[0] : null;
        var errorMessage = primaryError?.Message ?? "GraphQL operation failed";
        var mappedStatus = MapGraphQLErrorToStatusCode(primaryError?.Extensions?.Code);
        var errorType = MapCodeToErrorType(primaryError?.Extensions?.Code);

        return new GraphQLResult<T>(false, httpStatusCode, mappedStatus, default, errorMessage, errors, errorType);
    }

    /// <summary>
    /// Creates a failure result from a backend error.
    /// </summary>
    public static GraphQLResult<T> FromBackendError(int statusCode, string error, BackendErrorType errorType) =>
        new(false, statusCode, statusCode, default, error, null, errorType);

    /// <summary>
    /// Converts this GraphQL result to a standard BackendResult.
    /// Uses MappedStatusCode for proper HTTP status mapping.
    /// </summary>
    public BackendResult<T> ToBackendResult()
    {
        if (IsSuccess)
            return BackendResult<T>.Success(Data!, MappedStatusCode);

        return ErrorType switch
        {
            BackendErrorType.AuthenticationError => BackendResult<T>.AuthenticationFailure(Error!),
            BackendErrorType.AuthorizationError => BackendResult<T>.AuthorizationFailure(Error!),
            BackendErrorType.NetworkError => BackendResult<T>.NetworkFailure(Error!),
            BackendErrorType.Timeout => BackendResult<T>.TimeoutFailure(Error!),
            _ => BackendResult<T>.Failure(MappedStatusCode, Error!, ErrorType)
        };
    }

    /// <summary>
    /// Maps GraphQL error codes to HTTP status codes.
    /// </summary>
    private static int MapGraphQLErrorToStatusCode(string? code)
    {
        if (string.IsNullOrEmpty(code))
            return 400; // Default to Bad Request for GraphQL errors without code

        return code.ToUpperInvariant() switch
        {
            "NOT_FOUND" or "NOTFOUND" => 404,
            "UNAUTHORIZED" or "UNAUTHENTICATED" => 401,
            "FORBIDDEN" or "ACCESS_DENIED" => 403,
            "BAD_REQUEST" or "BAD_USER_INPUT" or "VALIDATION_ERROR" => 400,
            "CONFLICT" => 409,
            "INTERNAL_SERVER_ERROR" or "INTERNAL_ERROR" => 500,
            "SERVICE_UNAVAILABLE" => 503,
            "TIMEOUT" or "GATEWAY_TIMEOUT" => 504,
            "RATE_LIMITED" or "TOO_MANY_REQUESTS" => 429,
            "GRAPHQL_PARSE_FAILED" or "GRAPHQL_VALIDATION_FAILED" => 400,
            "PERSISTED_QUERY_NOT_FOUND" => 400,
            _ => 400 // Default to Bad Request for unknown codes
        };
    }

    /// <summary>
    /// Maps GraphQL error codes to BackendErrorType.
    /// </summary>
    private static BackendErrorType MapCodeToErrorType(string? code)
    {
        if (string.IsNullOrEmpty(code))
            return BackendErrorType.Unknown;

        return code.ToUpperInvariant() switch
        {
            "UNAUTHORIZED" or "UNAUTHENTICATED" => BackendErrorType.AuthenticationError,
            "FORBIDDEN" or "ACCESS_DENIED" => BackendErrorType.AuthorizationError,
            "INTERNAL_SERVER_ERROR" or "INTERNAL_ERROR" or "SERVICE_UNAVAILABLE" => BackendErrorType.ServerError,
            "TIMEOUT" or "GATEWAY_TIMEOUT" => BackendErrorType.Timeout,
            _ => BackendErrorType.Unknown
        };
    }
}

/// <summary>
/// Extension methods for GraphQL support in backend calling.
/// </summary>
public static class GraphQLExtensions
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Extracts a value from a JsonElement by path (e.g., "product" or "orders.items").
    /// </summary>
    /// <typeparam name="T">The expected type.</typeparam>
    /// <param name="element">The JSON element containing the data.</param>
    /// <param name="path">Dot-separated path to the value (e.g., "product", "user.orders").</param>
    /// <returns>The extracted and deserialized value.</returns>
    public static T? ExtractPath<T>(this JsonElement element, string path)
    {
        var current = element;
        var segments = path.Split('.');

        foreach (var segment in segments)
        {
            if (current.ValueKind != JsonValueKind.Object)
                return default;

            if (!current.TryGetProperty(segment, out var next))
            {
                // Try case-insensitive match
                var found = false;
                foreach (var prop in current.EnumerateObject())
                {
                    if (prop.Name.Equals(segment, StringComparison.OrdinalIgnoreCase))
                    {
                        next = prop.Value;
                        found = true;
                        break;
                    }
                }
                if (!found)
                    return default;
            }
            current = next;
        }

        if (current.ValueKind == JsonValueKind.Null)
            return default;

        return current.Deserialize<T>(JsonOptions);
    }

    /// <summary>
    /// Creates a GraphQL request object.
    /// </summary>
    public static GraphQLRequest CreateRequest(string query, object? variables = null, string? operationName = null)
    {
        return new GraphQLRequest
        {
            Query = query,
            Variables = variables,
            OperationName = operationName
        };
    }
}
