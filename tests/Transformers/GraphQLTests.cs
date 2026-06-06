using System.Text.Json;

namespace b17s.Porta.Tests.Transformers;

public sealed class GraphQLTests
{
    // -----------------------------
    // GraphQLResult<T>.Success
    // -----------------------------

    [Fact]
    public void Success_DefaultsHttpStatusTo200_AndMirrorsIntoMappedStatus()
    {
        var result = GraphQLResult<string>.Success("payload");

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.HttpStatusCode);
        Assert.Equal(200, result.MappedStatusCode);
        Assert.Equal("payload", result.Data);
        Assert.Null(result.Error);
        Assert.Null(result.Errors);
        Assert.Equal(BackendErrorType.None, result.ErrorType);
    }

    [Fact]
    public void Success_RespectsCustomHttpStatusCode()
    {
        // 2xx responses other than 200 (e.g. 201 Created from a mutation) must be
        // preserved so the surrounding BackendResult forwards the same status.
        var result = GraphQLResult<string>.Success("payload", httpStatusCode: 201);

        Assert.Equal(201, result.HttpStatusCode);
        Assert.Equal(201, result.MappedStatusCode);
    }

    // -----------------------------
    // GraphQLResult<T>.FromGraphQLErrors -> status-code mapping
    // -----------------------------

    [Theory]
    // Canonical error codes
    [InlineData("NOT_FOUND", 404)]
    [InlineData("NOTFOUND", 404)]
    [InlineData("UNAUTHORIZED", 401)]
    [InlineData("UNAUTHENTICATED", 401)]
    [InlineData("FORBIDDEN", 403)]
    [InlineData("ACCESS_DENIED", 403)]
    [InlineData("BAD_REQUEST", 400)]
    [InlineData("BAD_USER_INPUT", 400)]
    [InlineData("VALIDATION_ERROR", 400)]
    [InlineData("CONFLICT", 409)]
    [InlineData("INTERNAL_SERVER_ERROR", 500)]
    [InlineData("INTERNAL_ERROR", 500)]
    [InlineData("SERVICE_UNAVAILABLE", 503)]
    [InlineData("TIMEOUT", 504)]
    [InlineData("GATEWAY_TIMEOUT", 504)]
    [InlineData("RATE_LIMITED", 429)]
    [InlineData("TOO_MANY_REQUESTS", 429)]
    [InlineData("GRAPHQL_PARSE_FAILED", 400)]
    [InlineData("GRAPHQL_VALIDATION_FAILED", 400)]
    [InlineData("PERSISTED_QUERY_NOT_FOUND", 400)]
    // Codes are upper-cased before comparison, so input casing must not matter.
    [InlineData("not_found", 404)]
    [InlineData("Unauthorized", 401)]
    public void FromGraphQLErrors_MapsKnownExtensionCodes_ToHttpStatus(string code, int expectedStatus)
    {
        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "boom", Extensions = new GraphQLErrorExtensions { Code = code } },
        });

        Assert.False(result.IsSuccess);
        Assert.Equal(expectedStatus, result.MappedStatusCode);
        Assert.Equal("boom", result.Error);
    }

    [Fact]
    public void FromGraphQLErrors_UnknownExtensionCode_FallsBackTo400()
    {
        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "weird", Extensions = new GraphQLErrorExtensions { Code = "WEIRD_THING" } },
        });

        Assert.Equal(400, result.MappedStatusCode);
        Assert.Equal(BackendErrorType.Unknown, result.ErrorType);
    }

    [Fact]
    public void FromGraphQLErrors_MissingExtensions_DefaultsTo400_AndUnknownErrorType()
    {
        // Server returned an error object with no extensions/code at all. The spec
        // doesn't mandate a code, so we treat this as a generic 400.
        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "no code" },
        });

        Assert.Equal(400, result.MappedStatusCode);
        Assert.Equal(BackendErrorType.Unknown, result.ErrorType);
        Assert.Equal("no code", result.Error);
    }

    [Fact]
    public void FromGraphQLErrors_EmptyCodeString_DefaultsTo400()
    {
        // Empty-string code must not match any case; treat as no code.
        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "blank code", Extensions = new GraphQLErrorExtensions { Code = "" } },
        });

        Assert.Equal(400, result.MappedStatusCode);
        Assert.Equal(BackendErrorType.Unknown, result.ErrorType);
    }

    [Fact]
    public void FromGraphQLErrors_EmptyErrorList_FallsBackToGenericMessage()
    {
        // Caller-side defensive case: errors array exists but is empty. Treat as a
        // generic failure rather than crashing.
        var result = GraphQLResult<string>.FromGraphQLErrors(Array.Empty<GraphQLError>());

        Assert.False(result.IsSuccess);
        Assert.Equal("GraphQL operation failed", result.Error);
        Assert.Equal(400, result.MappedStatusCode);
    }

    [Fact]
    public void FromGraphQLErrors_UsesPrimaryErrorMessage_AndPreservesAllErrors()
    {
        // Only the first error drives the status/message, but the full list must
        // be preserved so downstream callers can surface every diagnostic.
        var errors = new[]
        {
            new GraphQLError { Message = "first", Extensions = new GraphQLErrorExtensions { Code = "NOT_FOUND" } },
            new GraphQLError { Message = "second" },
        };

        var result = GraphQLResult<string>.FromGraphQLErrors(errors);

        Assert.Equal("first", result.Error);
        Assert.Equal(404, result.MappedStatusCode);
        Assert.NotNull(result.Errors);
        Assert.Equal(2, result.Errors!.Count);
        Assert.Equal("second", result.Errors[1].Message);
    }

    [Fact]
    public void FromGraphQLErrors_PreservesHttpStatusCode_DistinctFromMappedStatus()
    {
        // GraphQL spec: errors usually arrive with HTTP 200. We keep the original
        // HTTP status (for logging/telemetry) but the *mapped* status is what the
        // client sees - they're intentionally different fields.
        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "x", Extensions = new GraphQLErrorExtensions { Code = "NOT_FOUND" } },
        }, httpStatusCode: 200);

        Assert.Equal(200, result.HttpStatusCode);
        Assert.Equal(404, result.MappedStatusCode);
    }

    // -----------------------------
    // GraphQLResult<T>.FromGraphQLErrors -> error type mapping
    // -----------------------------

    [Theory]
    [InlineData("UNAUTHORIZED", BackendErrorType.AuthenticationError)]
    [InlineData("UNAUTHENTICATED", BackendErrorType.AuthenticationError)]
    [InlineData("FORBIDDEN", BackendErrorType.AuthorizationError)]
    [InlineData("ACCESS_DENIED", BackendErrorType.AuthorizationError)]
    [InlineData("INTERNAL_SERVER_ERROR", BackendErrorType.ServerError)]
    [InlineData("INTERNAL_ERROR", BackendErrorType.ServerError)]
    [InlineData("SERVICE_UNAVAILABLE", BackendErrorType.ServerError)]
    [InlineData("TIMEOUT", BackendErrorType.Timeout)]
    [InlineData("GATEWAY_TIMEOUT", BackendErrorType.Timeout)]
    [InlineData("NOT_FOUND", BackendErrorType.Unknown)]
    [InlineData("BAD_REQUEST", BackendErrorType.Unknown)]
    public void FromGraphQLErrors_MapsExtensionCodesToErrorType(string code, BackendErrorType expected)
    {
        var result = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Extensions = new GraphQLErrorExtensions { Code = code } },
        });

        Assert.Equal(expected, result.ErrorType);
    }

    // -----------------------------
    // GraphQLResult<T>.FromBackendError
    // -----------------------------

    [Fact]
    public void FromBackendError_PreservesStatusErrorAndType()
    {
        var result = GraphQLResult<string>.FromBackendError(503, "down", BackendErrorType.ServerError);

        Assert.False(result.IsSuccess);
        Assert.Equal(503, result.HttpStatusCode);
        Assert.Equal(503, result.MappedStatusCode);
        Assert.Equal("down", result.Error);
        Assert.Equal(BackendErrorType.ServerError, result.ErrorType);
        Assert.Null(result.Errors);
    }

    // -----------------------------
    // GraphQLResult<T>.ToBackendResult
    // -----------------------------

    [Fact]
    public void ToBackendResult_OnSuccess_UsesMappedStatus_NotRawHttpStatus()
    {
        // Success path: mapped == http for 2xx, but the contract is that
        // ToBackendResult always uses MappedStatusCode - verify here so the
        // distinction is locked in.
        var graphQL = GraphQLResult<string>.Success("payload", httpStatusCode: 201);

        var backend = graphQL.ToBackendResult();

        Assert.True(backend.IsSuccess);
        Assert.Equal("payload", backend.Value);
        Assert.Equal(201, backend.StatusCode);
    }

    [Theory]
    [InlineData(BackendErrorType.AuthenticationError, 401)]
    [InlineData(BackendErrorType.AuthorizationError, 403)]
    [InlineData(BackendErrorType.NetworkError, 502)]
    [InlineData(BackendErrorType.Timeout, 504)]
    public void ToBackendResult_TypedFailures_ProjectToCorrectStatus(BackendErrorType errorType, int expectedStatus)
    {
        // The typed failure factories (Authentication/Authorization/Network/Timeout)
        // ignore MappedStatusCode and use their canonical status. This is intentional:
        // a 401 is a 401 regardless of what the GraphQL extension code mapping said.
        var graphQL = GraphQLResult<string>.FromBackendError(599, "x", errorType);

        var backend = graphQL.ToBackendResult();

        Assert.False(backend.IsSuccess);
        Assert.Equal(expectedStatus, backend.StatusCode);
        Assert.Equal(errorType, backend.ErrorType);
    }

    [Fact]
    public void ToBackendResult_GenericFailure_UsesMappedStatusCode()
    {
        // For non-typed failures (ClientError/ServerError/Unknown), the mapped
        // status comes from the extension-code mapping and must survive the
        // projection to BackendResult unchanged.
        var graphQL = GraphQLResult<string>.FromGraphQLErrors(new[]
        {
            new GraphQLError { Message = "rate", Extensions = new GraphQLErrorExtensions { Code = "RATE_LIMITED" } },
        });

        var backend = graphQL.ToBackendResult();

        Assert.False(backend.IsSuccess);
        Assert.Equal(429, backend.StatusCode);
        Assert.Equal("rate", backend.Error);
    }

    // -----------------------------
    // GraphQLExtensions.ExtractPath
    // -----------------------------

    [Fact]
    public void ExtractPath_TopLevelProperty_ReturnsDeserialized()
    {
        var json = JsonDocument.Parse("""{"product":{"id":42,"name":"widget"}}""").RootElement;

        var product = json.ExtractPath<Product>("product");

        Assert.NotNull(product);
        Assert.Equal(42, product!.Id);
        Assert.Equal("widget", product.Name);
    }

    [Fact]
    public void ExtractPath_NestedDotPath_FollowsSegments()
    {
        // "user.orders" must descend two levels before deserializing.
        var json = JsonDocument.Parse("""{"user":{"orders":[{"id":1},{"id":2}]}}""").RootElement;

        var orders = json.ExtractPath<List<Order>>("user.orders");

        Assert.NotNull(orders);
        Assert.Equal(2, orders!.Count);
        Assert.Equal(1, orders[0].Id);
    }

    [Fact]
    public void ExtractPath_PropertyNameMismatchCase_FallsBackToInsensitiveMatch()
    {
        // Backends differ on JSON casing; we accept camelCase or PascalCase along
        // the path so callers don't need to know the server's convention.
        var json = JsonDocument.Parse("""{"Product":{"id":7}}""").RootElement;

        var product = json.ExtractPath<Product>("product");

        Assert.NotNull(product);
        Assert.Equal(7, product!.Id);
    }

    [Fact]
    public void ExtractPath_MissingSegment_ReturnsDefault()
    {
        var json = JsonDocument.Parse("""{"product":{"id":1}}""").RootElement;

        var missing = json.ExtractPath<Product>("user");

        Assert.Null(missing);
    }

    [Fact]
    public void ExtractPath_TraversesIntoNonObject_ReturnsDefault()
    {
        // Once we hit a scalar/array mid-traversal, we cannot continue descending.
        // Return default rather than throwing.
        var json = JsonDocument.Parse("""{"product":[1,2,3]}""").RootElement;

        var nested = json.ExtractPath<Product>("product.id");

        Assert.Null(nested);
    }

    [Fact]
    public void ExtractPath_TerminalNull_ReturnsDefault()
    {
        // {"product": null} - the path resolves but the value is JSON null.
        // We must return default to avoid surfacing a "null reference"-shaped object.
        var json = JsonDocument.Parse("""{"product":null}""").RootElement;

        var product = json.ExtractPath<Product>("product");

        Assert.Null(product);
    }

    [Fact]
    public void ExtractPath_DeserializesValuesCamelCase()
    {
        // The shared JsonSerializerOptions enable camelCase + case-insensitivity;
        // verify a camelCase JSON property maps onto a PascalCase C# property.
        var json = JsonDocument.Parse("""{"data":{"userName":"ada"}}""").RootElement;

        var user = json.ExtractPath<UserDto>("data");

        Assert.NotNull(user);
        Assert.Equal("ada", user!.UserName);
    }

    // -----------------------------
    // GraphQLExtensions.CreateRequest
    // -----------------------------

    [Fact]
    public void CreateRequest_QueryOnly_OmitsOperationNameAndVariablesInJson()
    {
        // [JsonIgnore(WhenWritingNull)] - the serialized payload must not include
        // null operationName / null variables, because some GraphQL servers reject
        // a literal `null` for those fields.
        var request = GraphQLExtensions.CreateRequest("{ ping }");

        var json = JsonSerializer.Serialize(request);

        Assert.Contains("\"query\":\"{ ping }\"", json);
        Assert.DoesNotContain("operationName", json);
        Assert.DoesNotContain("variables", json);
    }

    [Fact]
    public void CreateRequest_WithVariablesAndOperationName_IncludesBothInJson()
    {
        var request = GraphQLExtensions.CreateRequest(
            "query GetUser($id: ID!) { user(id: $id) { name } }",
            variables: new { id = "u1" },
            operationName: "GetUser");

        var json = JsonSerializer.Serialize(request);

        Assert.Contains("\"operationName\":\"GetUser\"", json);
        Assert.Contains("\"variables\":{\"id\":\"u1\"}", json);
    }

    private sealed class Product
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";
    }

    private sealed class Order
    {
        public int Id { get; set; }
    }

    private sealed class UserDto
    {
        public string UserName { get; set; } = "";
    }
}
