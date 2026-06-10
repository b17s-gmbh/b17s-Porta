using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

using Microsoft.Extensions.DependencyInjection;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// Registration-time validation for AddTransformer / AddTransformerTypes: both bind to
/// the <see cref="ITransformer"/> marker so a non-transformer type fails at registration
/// (or compile time) instead of surfacing as a request-time resolution surprise.
/// </summary>
public class TransformerExtensionsTests
{
    private sealed class Ping;

    private sealed class ValidTransformer : ITransformer<string>
    {
        public Task<string> TransformAsync(TransformerContext context) => Task.FromResult("ok");
    }

    private sealed class ValidBodyTransformer : ITransformer<Ping, string>
    {
        public Task<string> TransformAsync(Ping? request, TransformerContext context) => Task.FromResult("ok");
    }

    private sealed class NotATransformer;

    [Fact]
    public void AddTransformer_RegistersScopedDescriptor()
    {
        var services = new ServiceCollection();

        services.AddTransformer<ValidTransformer>();

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(ValidTransformer));
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
    }

    [Fact]
    public void AddTransformerTypes_RegistersScopedDescriptors_ForBothInterfaceShapes()
    {
        var services = new ServiceCollection();

        services.AddTransformerTypes(typeof(ValidTransformer), typeof(ValidBodyTransformer));

        Assert.Single(services, d => d.ServiceType == typeof(ValidTransformer) && d.Lifetime == ServiceLifetime.Scoped);
        Assert.Single(services, d => d.ServiceType == typeof(ValidBodyTransformer) && d.Lifetime == ServiceLifetime.Scoped);
    }

    [Fact]
    public void AddTransformerTypes_NonTransformerType_ThrowsArgumentException()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<ArgumentException>(
            () => services.AddTransformerTypes(typeof(NotATransformer)));

        Assert.Equal("transformerTypes", ex.ParamName);
        Assert.Contains(nameof(NotATransformer), ex.Message);
    }

    [Fact]
    public void AddTransformer_NullServices_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => ((IServiceCollection)null!).AddTransformer<ValidTransformer>());

    [Fact]
    public void AddTransformerTypes_NullServices_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => ((IServiceCollection)null!).AddTransformerTypes(typeof(ValidTransformer)));

    [Fact]
    public void AddTransformerTypes_NullTypesArray_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => new ServiceCollection().AddTransformerTypes(null!));
}
