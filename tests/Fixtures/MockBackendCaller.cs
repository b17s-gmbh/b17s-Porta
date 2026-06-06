namespace b17s.Porta.Tests.Fixtures;

/// <summary>
/// Mock implementation of IBackendCaller for unit testing.
/// Allows configuring responses for specific URLs or patterns.
/// </summary>
public class MockBackendCaller : IBackendCaller
{
    private readonly Dictionary<string, object> _responses = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, BackendResult> _noContentResponses = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, object> _graphqlResponses = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<RecordedCall> _recordedCalls = [];
    private Func<BackendRequest, object?>? _defaultHandler;
    private int _delayMs;

    /// <summary>
    /// Gets the list of all recorded calls made to this mock.
    /// </summary>
    public IReadOnlyList<RecordedCall> RecordedCalls => _recordedCalls.AsReadOnly();

    /// <summary>
    /// Gets the last recorded call, or null if no calls have been made.
    /// </summary>
    public RecordedCall? LastCall => _recordedCalls.Count > 0 ? _recordedCalls[^1] : null;

    /// <summary>
    /// Configures a successful response for a specific URL pattern.
    /// </summary>
    public MockBackendCaller SetupResponse<TResponse>(string urlPattern, TResponse response)
    {
        _responses[urlPattern] = BackendResult<TResponse>.Success(response!);
        return this;
    }

    /// <summary>
    /// Configures a successful response with a specific status code.
    /// </summary>
    public MockBackendCaller SetupResponse<TResponse>(string urlPattern, TResponse response, int statusCode)
    {
        _responses[urlPattern] = BackendResult<TResponse>.Success(response!, statusCode);
        return this;
    }

    /// <summary>
    /// Configures a failure response for a specific URL pattern.
    /// </summary>
    public MockBackendCaller SetupFailure<TResponse>(string urlPattern, int statusCode, string error, BackendErrorType errorType = BackendErrorType.Unknown)
    {
        _responses[urlPattern] = BackendResult<TResponse>.Failure(statusCode, error, errorType);
        return this;
    }

    /// <summary>
    /// Configures an authentication failure (401) for a specific URL pattern.
    /// </summary>
    public MockBackendCaller SetupAuthenticationFailure<TResponse>(string urlPattern, string error = "Unauthorized")
    {
        _responses[urlPattern] = BackendResult<TResponse>.AuthenticationFailure(error);
        return this;
    }

    /// <summary>
    /// Configures an authorization failure (403) for a specific URL pattern.
    /// </summary>
    public MockBackendCaller SetupAuthorizationFailure<TResponse>(string urlPattern, string error = "Forbidden")
    {
        _responses[urlPattern] = BackendResult<TResponse>.AuthorizationFailure(error);
        return this;
    }

    /// <summary>
    /// Configures a network failure (502) for a specific URL pattern.
    /// </summary>
    public MockBackendCaller SetupNetworkFailure<TResponse>(string urlPattern, string error = "Network error")
    {
        _responses[urlPattern] = BackendResult<TResponse>.NetworkFailure(error);
        return this;
    }

    /// <summary>
    /// Configures a timeout failure (504) for a specific URL pattern.
    /// </summary>
    public MockBackendCaller SetupTimeoutFailure<TResponse>(string urlPattern, string error = "Request timed out")
    {
        _responses[urlPattern] = BackendResult<TResponse>.TimeoutFailure(error);
        return this;
    }

    /// <summary>
    /// Configures a successful no-content response for a specific URL pattern.
    /// </summary>
    public MockBackendCaller SetupNoContentResponse(string urlPattern, int statusCode = 204)
    {
        _noContentResponses[urlPattern] = BackendResult.Success(statusCode);
        return this;
    }

    /// <summary>
    /// Configures a failure for no-content calls.
    /// </summary>
    public MockBackendCaller SetupNoContentFailure(string urlPattern, int statusCode, string error, BackendErrorType errorType = BackendErrorType.Unknown)
    {
        _noContentResponses[urlPattern] = BackendResult.Failure(statusCode, error, errorType);
        return this;
    }

    /// <summary>
    /// Configures a successful GraphQL response for a specific URL pattern.
    /// </summary>
    public MockBackendCaller SetupGraphQLResponse<TResponse>(string urlPattern, TResponse response)
    {
        _graphqlResponses[urlPattern] = GraphQLResult<TResponse>.Success(response!);
        return this;
    }

    /// <summary>
    /// Configures a GraphQL error response for a specific URL pattern.
    /// </summary>
    public MockBackendCaller SetupGraphQLError<TResponse>(string urlPattern, string errorMessage, string? errorCode = null)
    {
        var errors = new List<GraphQLError>
        {
            new()
            {
                Message = errorMessage,
                Extensions = errorCode != null ? new GraphQLErrorExtensions { Code = errorCode } : null
            }
        };
        _graphqlResponses[urlPattern] = GraphQLResult<TResponse>.FromGraphQLErrors(errors);
        return this;
    }

    /// <summary>
    /// Sets a default handler for requests that don't match any configured patterns.
    /// </summary>
    public MockBackendCaller SetDefaultHandler(Func<BackendRequest, object?> handler)
    {
        _defaultHandler = handler;
        return this;
    }

    /// <summary>
    /// Configures an artificial delay for all calls (simulates network latency).
    /// </summary>
    public MockBackendCaller WithDelay(int milliseconds)
    {
        _delayMs = milliseconds;
        return this;
    }

    /// <summary>
    /// Clears all recorded calls.
    /// </summary>
    public void ClearRecordedCalls()
    {
        _recordedCalls.Clear();
    }

    /// <summary>
    /// Resets all configured responses and recorded calls.
    /// </summary>
    public void Reset()
    {
        _responses.Clear();
        _noContentResponses.Clear();
        _graphqlResponses.Clear();
        _recordedCalls.Clear();
        _defaultHandler = null;
        _delayMs = 0;
    }

    public async Task<BackendResult<TResponse>> CallAsync<TResponse>(BackendRequest request, CancellationToken cancellationToken)
    {
        await SimulateDelayAsync(cancellationToken);

        _recordedCalls.Add(new RecordedCall(request, null));

        var result = FindResponse<TResponse>(request.Url);
        if (result != null)
        {
            return result.Value;
        }

        if (_defaultHandler != null)
        {
            var defaultResult = _defaultHandler(request);
            if (defaultResult is BackendResult<TResponse> typedResult)
            {
                return typedResult;
            }
        }

        throw new InvalidOperationException(
            $"No response configured for URL: {request.Url}. " +
            $"Use SetupResponse<{typeof(TResponse).Name}>(\"{request.Url}\", response) to configure a response.");
    }

    public async Task<BackendResult<TResponse>> CallAsync<TRequest, TResponse>(BackendRequest request, TRequest body, CancellationToken cancellationToken)
    {
        await SimulateDelayAsync(cancellationToken);

        _recordedCalls.Add(new RecordedCall(request, body));

        var result = FindResponse<TResponse>(request.Url);
        if (result != null)
        {
            return result.Value;
        }

        if (_defaultHandler != null)
        {
            var defaultResult = _defaultHandler(request);
            if (defaultResult is BackendResult<TResponse> typedResult)
            {
                return typedResult;
            }
        }

        throw new InvalidOperationException(
            $"No response configured for URL: {request.Url}. " +
            $"Use SetupResponse<{typeof(TResponse).Name}>(\"{request.Url}\", response) to configure a response.");
    }

    public async Task<BackendResult> CallAsync(BackendRequest request, CancellationToken cancellationToken)
    {
        await SimulateDelayAsync(cancellationToken);

        _recordedCalls.Add(new RecordedCall(request, null));

        if (_noContentResponses.TryGetValue(request.Url, out var result))
        {
            return result;
        }

        // Check for partial matches
        foreach (var (pattern, response) in _noContentResponses)
        {
            if (request.Url.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return response;
            }
        }

        // Default to success
        return BackendResult.Success();
    }

    public async Task<BackendResult> CallAsync<TRequest>(BackendRequest request, TRequest body, CancellationToken cancellationToken)
    {
        await SimulateDelayAsync(cancellationToken);

        _recordedCalls.Add(new RecordedCall(request, body));

        if (_noContentResponses.TryGetValue(request.Url, out var result))
        {
            return result;
        }

        // Check for partial matches
        foreach (var (pattern, response) in _noContentResponses)
        {
            if (request.Url.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return response;
            }
        }

        // Default to success
        return BackendResult.Success();
    }

    public async Task<BackendObjectResult> CallAsync(BackendRequest request, Type responseType, CancellationToken cancellationToken)
    {
        await SimulateDelayAsync(cancellationToken);

        _recordedCalls.Add(new RecordedCall(request, null));

        // Try exact match first
        if (_responses.TryGetValue(request.Url, out var exactMatch))
        {
            return ExtractObjectResult(exactMatch);
        }

        // Try partial matches
        foreach (var (pattern, response) in _responses)
        {
            if (request.Url.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return ExtractObjectResult(response);
            }
        }

        if (_defaultHandler != null)
        {
            var defaultResult = _defaultHandler(request);
            if (defaultResult != null)
            {
                return BackendObjectResult.Success(defaultResult);
            }
        }

        throw new InvalidOperationException(
            $"No response configured for URL: {request.Url} with type {responseType.Name}.");
    }

    public async Task<BackendObjectResult> CallWithBodyAsync(BackendRequest request, object body, Type responseType, CancellationToken cancellationToken)
    {
        await SimulateDelayAsync(cancellationToken);

        _recordedCalls.Add(new RecordedCall(request, body));

        // Try exact match first
        if (_responses.TryGetValue(request.Url, out var exactMatch))
        {
            return ExtractObjectResult(exactMatch);
        }

        // Try partial matches
        foreach (var (pattern, response) in _responses)
        {
            if (request.Url.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return ExtractObjectResult(response);
            }
        }

        if (_defaultHandler != null)
        {
            var defaultResult = _defaultHandler(request);
            if (defaultResult != null)
            {
                return BackendObjectResult.Success(defaultResult);
            }
        }

        throw new InvalidOperationException(
            $"No response configured for URL: {request.Url} with type {responseType.Name}.");
    }

    public async Task<GraphQLResult<TResponse>> CallGraphQLAsync<TResponse>(
        BackendRequest request,
        string query,
        object? variables,
        string dataPath,
        string? operationName = null,
        CancellationToken cancellationToken = default)
    {
        await SimulateDelayAsync(cancellationToken);

        _recordedCalls.Add(new RecordedCall(request, new { query, variables, operationName }));

        // Check for configured GraphQL responses
        if (_graphqlResponses.TryGetValue(request.Url, out var graphqlResult))
        {
            return (GraphQLResult<TResponse>)graphqlResult;
        }

        // Check for partial matches
        foreach (var (pattern, response) in _graphqlResponses)
        {
            if (request.Url.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return (GraphQLResult<TResponse>)response;
            }
        }

        // Try regular responses as fallback
        var result = FindResponse<TResponse>(request.Url);
        if (result != null)
        {
            if (result.Value.IsSuccess)
            {
                return GraphQLResult<TResponse>.Success(result.Value.Value!);
            }
            return GraphQLResult<TResponse>.FromBackendError(
                result.Value.StatusCode,
                result.Value.Error ?? "Unknown error",
                result.Value.ErrorType);
        }

        throw new InvalidOperationException(
            $"No GraphQL response configured for URL: {request.Url}. " +
            $"Use SetupGraphQLResponse<{typeof(TResponse).Name}>(\"{request.Url}\", response) to configure a response.");
    }

    public Task<RawBackendResult> CallRawAsync(BackendRequest request, CancellationToken cancellationToken)
    {
        _recordedCalls.Add(new RecordedCall(request, null));
        throw new NotImplementedException("CallRawAsync is not implemented in MockBackendCaller. Add mock support if needed.");
    }

    public Task<RawBackendResult> CallRawAsync(BackendRequest request, Stream requestBody, string contentType, CancellationToken cancellationToken)
    {
        _recordedCalls.Add(new RecordedCall(request, new { requestBody, contentType }));
        throw new NotImplementedException("CallRawAsync with body is not implemented in MockBackendCaller. Add mock support if needed.");
    }

    private static BackendObjectResult ExtractObjectResult(object backendResult)
    {
        // Use reflection to extract value from BackendResult<T>
        var resultType = backendResult.GetType();
        var isSuccessProperty = resultType.GetProperty("IsSuccess");
        var valueProperty = resultType.GetProperty("Value");
        var statusCodeProperty = resultType.GetProperty("StatusCode");
        var errorProperty = resultType.GetProperty("Error");
        var errorTypeProperty = resultType.GetProperty("ErrorType");

        var isSuccess = (bool)isSuccessProperty!.GetValue(backendResult)!;
        var statusCode = (int)statusCodeProperty!.GetValue(backendResult)!;

        if (isSuccess)
        {
            var value = valueProperty?.GetValue(backendResult);
            return BackendObjectResult.Success(value, statusCode);
        }
        else
        {
            var error = (string?)errorProperty?.GetValue(backendResult) ?? "Unknown error";
            var errorType = (BackendErrorType)errorTypeProperty!.GetValue(backendResult)!;
            return BackendObjectResult.Failure(statusCode, error, errorType);
        }
    }

    private BackendResult<TResponse>? FindResponse<TResponse>(string url)
    {
        // Try exact match first
        if (_responses.TryGetValue(url, out var exactMatch) && exactMatch is BackendResult<TResponse> exactResult)
        {
            return exactResult;
        }

        // Try partial matches (for URL patterns)
        foreach (var (pattern, response) in _responses)
        {
            if (url.Contains(pattern, StringComparison.OrdinalIgnoreCase) && response is BackendResult<TResponse> partialResult)
            {
                return partialResult;
            }
        }

        return null;
    }

    private async Task SimulateDelayAsync(CancellationToken cancellationToken)
    {
        if (_delayMs > 0)
        {
            await Task.Delay(_delayMs, cancellationToken);
        }
    }
}

/// <summary>
/// Represents a recorded call to the mock backend caller.
/// </summary>
public record RecordedCall(BackendRequest Request, object? Body)
{
    /// <summary>
    /// Gets the request body cast to the specified type.
    /// </summary>
    public TBody? GetBody<TBody>() => Body is TBody typed ? typed : default;
}
