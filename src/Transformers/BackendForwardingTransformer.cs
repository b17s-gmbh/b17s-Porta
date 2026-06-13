using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Transformers;

/// <summary>
/// Synthetic transformer used by <see cref="b17s.Porta.Extensions.PassThroughEndpointBuilder{TResponse}"/>.
/// Forwards the request to the backend via <see cref="IBackendCaller"/> and returns the deserialized
/// response, so pass-through endpoints share the full transformer pipeline (telemetry, auth folding,
/// When-predicates, anonymous-smuggling defense) instead of re-implementing it.
/// </summary>
internal sealed class BackendForwardingTransformer<TResponse> : ITransformer<TResponse>
{
    public async Task<TResponse> TransformAsync(TransformerContext context)
    {
        var backendRequest = (BackendRequest)context.Properties["BackendRequest"];
        var result = await context.BackendCaller.CallAsync<TResponse>(backendRequest, context.CancellationToken);

        if (result.IsSuccess)
        {
            return result.Value!;
        }

        // BackendResult.StatusCode is already mapped by IBackendErrorMapper inside
        // BackendCaller (default: 401/403 -> 502) - both for backend HTTP errors and for
        // transport/auth-stage failures such as an auth-handler exception (MapSendFailure),
        // so no re-mapping here.
        // Writing the response here sets HasStarted; the outer handler then skips
        // its own WriteAsJsonAsync.
        context.HttpContext.Response.StatusCode = result.StatusCode;
        await context.HttpContext.Response.WriteAsJsonAsync(
            new { error = result.Error ?? "Backend request failed" },
            context.CancellationToken);
        return default!;
    }
}
