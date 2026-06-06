namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Regression for B4 (security review): both BFF.BackendCaller named HttpClients must
/// have auto-redirect disabled on their primary handler. TrustedHostValidator only
/// runs at startup against the configured UrlTemplate, so a backend returning
/// `302 Location: https://attacker/...` would otherwise cause the client to follow
/// without re-validating, leaking custom headers added by IBackendAuthHandler
/// (X-Api-Key, HMAC signatures, etc.) - .NET only strips Authorization on
/// cross-origin redirects, not arbitrary custom headers.
/// </summary>
public sealed class BackendCallerRedirectTests
{
    [Theory]
    [InlineData(BackendCaller.HttpClientName)]
    [InlineData(BackendCaller.HttpClientNameWithRetries)]
    public void AddPortaCore_BackendCaller_DisablesAutoRedirect(string clientName)
    {
        var services = new ServiceCollection();
        services.AddPortaCore();
        using var provider = services.BuildServiceProvider();

        var factory = provider.GetRequiredService<IHttpMessageHandlerFactory>();
        using var handler = factory.CreateHandler(clientName);

        var primary = FindPrimaryHandler(handler);
        Assert.IsType<SocketsHttpHandler>(primary);
        Assert.False(((SocketsHttpHandler)primary).AllowAutoRedirect,
            $"'{clientName}' must have AllowAutoRedirect = false to prevent token exfiltration via compromised-backend 302 responses.");
    }

    private static HttpMessageHandler FindPrimaryHandler(HttpMessageHandler root)
    {
        var current = root;
        while (current is DelegatingHandler d && d.InnerHandler is not null)
        {
            current = d.InnerHandler;
        }
        return current;
    }
}
