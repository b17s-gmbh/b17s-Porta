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
/// <remarks>
/// Uses the declarative <see cref="AggregatingTransformer{TResponse}"/>: <see cref="Configure"/>
/// names the backends (and their response types), Porta runs them in parallel with a child
/// telemetry span each, and <see cref="MapResults"/> reads the typed results back by name.
/// </remarks>
internal sealed class UserDashboardTransformer(IConfiguration configuration)
    : AggregatingTransformer<DashboardResponse>
{
    private readonly string _provider = configuration["Demo:ProviderLabel"] ?? "OIDC";

    protected override void Configure(AggregatorBuilder builder)
    {
        builder.Backend<BackendIdentity>("me");
        builder.Backend<WeatherForecast[]>("weather");
        builder.Backend<InternalResource>("internal");
    }

    protected override DashboardResponse MapResults(AggregatorResults results, TransformerContext context)
        => new(
            _provider,
            results.Get<BackendIdentity>("me"),
            results.Get<WeatherForecast[]>("weather") ?? [],
            results.Get<InternalResource>("internal"));
}
