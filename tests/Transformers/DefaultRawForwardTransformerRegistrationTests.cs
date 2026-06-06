namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Regression: the zero-code MapRawForward() overloads default to
/// RawForwardEndpointBuilder&lt;DefaultRawForwardTransformer&gt;, which resolves the
/// transformer from DI at request time via GetRequiredService. AddPortaCore() must
/// therefore register DefaultRawForwardTransformer, or every documented no-transformer
/// proxy endpoint throws "No service for type 'DefaultRawForwardTransformer'" at runtime.
/// </summary>
public sealed class DefaultRawForwardTransformerRegistrationTests
{
    [Fact]
    public void AddPortaCore_RegistersDefaultRawForwardTransformer()
    {
        var services = new ServiceCollection();
        services.AddPortaCore();
        using var provider = services.BuildServiceProvider();

        // Resolve through a request scope, mirroring how RawForwardEndpointBuilder resolves
        // it from context.RequestServices at request time.
        using var scope = provider.CreateScope();
        var transformer = scope.ServiceProvider.GetRequiredService<DefaultRawForwardTransformer>();

        Assert.NotNull(transformer);
    }
}
