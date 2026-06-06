using b17s.Porta.Transformers;

namespace Demo.Bff;

/// <summary>
/// Demonstrates Porta's aggregation pattern with MIXED per-backend auth: a single BFF endpoint
/// (<c>/api/dashboard</c>) fans out to three backend calls in parallel and composes one response.
/// Backend URLs and per-backend auth policies come from <c>ToBackends(...)</c> in the endpoint
/// registration - <c>me</c> forwards the user's token (BearerToken), <c>weather</c> is public
/// (None), and <c>internal</c> uses the BFF's service credentials (BasicAuth). The transformer
/// itself is auth-agnostic: it just names the backends and Porta applies each one's policy.
/// </summary>
internal sealed class UserDashboardTransformer(IConfiguration configuration)
    : MultiBackendTransformer<DashboardResponse>
{
    private readonly string _provider = configuration["Demo:ProviderLabel"] ?? "OIDC";

    public override async Task<DashboardResponse> TransformAsync(TransformerContext context)
    {
        var results = await CallBackendsInParallelSafeAsync<object>(
        [
            async ct => (await CallNamedBackendAsync<BackendIdentity>("me", context, cancellationToken: ct)).Value,
            async ct => (await CallNamedBackendAsync<WeatherForecast[]>("weather", context, cancellationToken: ct)).Value,
            async ct => (await CallNamedBackendAsync<InternalResource>("internal", context, cancellationToken: ct)).Value,
        ], context);

        var identity = results[0] as BackendIdentity;
        var weather = results[1] as WeatherForecast[];
        var internalResource = results[2] as InternalResource;

        return new DashboardResponse(_provider, identity, weather ?? [], internalResource);
    }
}
