namespace b17s.Porta.Extensions;

/// <summary>
/// Names of the named <see cref="HttpClient"/>s Porta registers with <c>IHttpClientFactory</c>.
/// Use them to customize a client after registration, e.g. to add a proxy or a message handler:
/// <code>
/// builder.Services.AddHttpClient(PortaHttpClients.Backend)
///     .AddHttpMessageHandler&lt;MyHandler&gt;();
/// </code>
/// </summary>
public static class PortaHttpClients
{
    /// <summary>
    /// Backend calls from transformers, pass-through and raw-forward endpoints (registered by <c>AddPortaCore</c>).
    /// </summary>
    public const string Backend = "Porta.BackendCaller";

    /// <summary>
    /// Backend calls for requests with retries enabled (registered by <c>AddPortaCore</c> with the
    /// retry pipeline from <c>PortaCore:MaxRetryAttempts</c>).
    /// </summary>
    public const string BackendWithRetries = "Porta.BackendCaller.WithRetries";

    /// <summary>
    /// Calls to the identity provider: OIDC discovery, token refresh, token exchange, revocation and
    /// client credentials (registered by the authentication extensions).
    /// </summary>
    public const string Token = "Porta.TokenClient";

    /// <summary>
    /// RFC 7662 token introspection for reference tokens (registered by <c>AddReferenceTokenAuthentication</c>,
    /// <c>AddPortaReferenceTokenScheme</c> and <c>AddReferenceTokenService</c>).
    /// </summary>
    public const string ReferenceTokenIntrospection = "ReferenceTokenIntrospection";
}
