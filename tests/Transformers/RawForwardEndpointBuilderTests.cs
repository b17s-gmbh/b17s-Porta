using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Transformers;

public class RawForwardEndpointBuilderTests
{
    private static RawForwardEndpointBuilder<DefaultRawForwardTransformer> CreateBuilder(
        IBackendAuthHandlerRegistry? registry = null)
    {
        var serviceCollection = new ServiceCollection();
        if (registry != null)
        {
            serviceCollection.AddSingleton(registry);
        }
        var services = serviceCollection.BuildServiceProvider();
        var app = WebApplication.CreateBuilder(new WebApplicationOptions()).Build();
        return new RawForwardEndpointBuilder<DefaultRawForwardTransformer>(app, services);
    }

    private static (WebApplication App, RawForwardEndpointBuilder<TTransformer> Builder) CreateBuilderFor<TTransformer>(
        PortaCoreOptions? options = null)
        where TTransformer : class, IRawTransformer
    {
        var appBuilder = WebApplication.CreateBuilder(new WebApplicationOptions());
        if (options != null)
        {
            appBuilder.Services.AddSingleton(Options.Create(options));
        }
        var app = appBuilder.Build();
        return (app, new RawForwardEndpointBuilder<TTransformer>(app, app.Services));
    }

    [Fact]
    public void Build_WithUnknownBackendAuthPolicy_ThrowsWithClearError()
    {
        var registry = new BackendAuthHandlerRegistry();
        registry.Register(new NoneAuthHandler());

        var builder = CreateBuilder(registry)
            .FromRoute("GET", "/api/things")
            .ToBackend("GET", "https://backend.example.com/things")
            .WithBackendAuth("BAsicAUth"); // typo: should be "BasicAuth"

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("BAsicAUth", ex.Message);
        Assert.Contains("Unknown backend auth policy", ex.Message);
    }

    [Fact]
    public void Build_WithRegisteredBackendAuthPolicy_DoesNotThrow()
    {
        var registry = new BackendAuthHandlerRegistry();
        registry.Register(new NoneAuthHandler());

        var builder = CreateBuilder(registry)
            .FromRoute("GET", "/api/things")
            .ToBackend("GET", "https://backend.example.com/things")
            .WithBackendAuth(BackendAuthPolicies.None);

        var ex = Record.Exception(() => builder.Build());
        Assert.Null(ex);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    public void ToVerbSugar_SetsBackendMethodAndUrl(string verb)
    {
        // The To{Verb} shorthands on the raw-forward builder delegate to ToBackend("VERB", url),
        // mirroring the transformer builder's sugar so docs read the same across both builders.
        var builder = CreateBuilder();
        const string url = "https://backend.example.com/files/{id}";

        var configured = verb switch
        {
            "GET" => builder.ToGet(url),
            "POST" => builder.ToPost(url),
            "PUT" => builder.ToPut(url),
            "DELETE" => builder.ToDelete(url),
            "PATCH" => builder.ToPatch(url),
            _ => throw new ArgumentOutOfRangeException(nameof(verb)),
        };

        var (method, configuredUrl) = configured.GetConfiguredBackendForTesting();
        Assert.Equal(verb, method);
        Assert.Equal(url, configuredUrl);
    }

    [Fact]
    public void AllowForwardingHeaders_AddsHeadersToAllowList()
    {
        var builder = CreateBuilder();

        builder.AllowForwardingHeaders(["Authorization", "Cookie"]);

        var passThrough = builder.GetConfiguredHeaderPassThroughForTesting();
        Assert.NotNull(passThrough);
        Assert.Contains("Authorization", passThrough!.AllowedHeaders);
        Assert.Contains("Cookie", passThrough.AllowedHeaders);
        Assert.Empty(passThrough.AllowedDestinationHosts);
    }

    [Fact]
    public void AllowForwardingHeaders_WithDestinationHosts_PopulatesHostScope()
    {
        var builder = CreateBuilder();

        builder.AllowForwardingHeaders(
            headers: ["Authorization"],
            destinationHosts: ["internal.example.com", "trusted.example.com"]);

        var passThrough = builder.GetConfiguredHeaderPassThroughForTesting();
        Assert.NotNull(passThrough);
        Assert.Contains("internal.example.com", passThrough!.AllowedDestinationHosts);
        Assert.Contains("trusted.example.com", passThrough.AllowedDestinationHosts);
    }

    [Fact]
    public void AllowForwardingHeaders_HeaderLookupIsCaseInsensitive()
    {
        var builder = CreateBuilder();

        builder.AllowForwardingHeaders(["Authorization"]);

        var passThrough = builder.GetConfiguredHeaderPassThroughForTesting();
        Assert.NotNull(passThrough);
        // The pass-through HashSet uses OrdinalIgnoreCase and should round-trip case
        Assert.Contains("authorization", passThrough!.AllowedHeaders);
        Assert.Contains("AUTHORIZATION", passThrough.AllowedHeaders);
    }

    [Fact]
    public void AllowForwardingHeaders_HostLookupIsCaseInsensitive()
    {
        var builder = CreateBuilder();

        builder.AllowForwardingHeaders(["Authorization"], ["Internal.Example.Com"]);

        var passThrough = builder.GetConfiguredHeaderPassThroughForTesting();
        Assert.NotNull(passThrough);
        Assert.Contains("internal.example.com", passThrough!.AllowedDestinationHosts);
    }

    [Fact]
    public void Builder_WithoutAllowList_HasNullPassThrough_FallingBackToOptionsDefault()
    {
        var builder = CreateBuilder();

        // No call to AllowForwardingHeaders ⇒ per-endpoint allow-list remains null.
        // At Build() time the handler captures _options.DefaultRawForwardHeaderPassThrough instead.
        Assert.Null(builder.GetConfiguredHeaderPassThroughForTesting());
    }

    // The captive-dep regression guard: Build() must never instantiate
    // TTransformer, because at startup the only available IServiceProvider is
    // the root, and any scoped/HttpContext-bound dep on the transformer would
    // be captured from the root.
    [Fact]
    public void Build_DoesNotInstantiateTransformer()
    {
        var (_, builder) = CreateBuilderFor<ConstructorThrowsTransformer>(
            new PortaCoreOptions { RequireAuthorizationByDefault = false });

        var ex = Record.Exception(() => builder
            .FromRoute("GET", "/probe")
            .ToBackend("GET", "https://backend.example.com/probe")
            .Build());

        Assert.Null(ex);
    }

    [Fact]
    public void Build_TransformerWithRequiresAuthenticationAttribute_AddsAuthorizationMetadata()
    {
        var (app, builder) = CreateBuilderFor<AuthRequiredTransformer>(
            new PortaCoreOptions { RequireAuthorizationByDefault = false });

        builder
            .FromRoute("GET", "/secure")
            .ToBackend("GET", "https://backend.example.com/secure")
            .Build();

        var endpoint = SingleEndpoint(app);
        Assert.NotNull(endpoint.Metadata.GetMetadata<IAuthorizeData>());
        Assert.Null(endpoint.Metadata.GetMetadata<IAllowAnonymous>());
    }

    [Fact]
    public void Build_TransformerWithoutAttribute_AndDefaultAnonymous_AllowsAnonymous()
    {
        var (app, builder) = CreateBuilderFor<DefaultRawForwardTransformer>(
            new PortaCoreOptions { RequireAuthorizationByDefault = false });

        builder
            .FromRoute("GET", "/open")
            .ToBackend("GET", "https://backend.example.com/open")
            .Build();

        var endpoint = SingleEndpoint(app);
        Assert.NotNull(endpoint.Metadata.GetMetadata<IAllowAnonymous>());
    }

    private static Microsoft.AspNetCore.Http.Endpoint SingleEndpoint(WebApplication app)
    {
        // WebApplication implements IEndpointRouteBuilder, exposing DataSources
        // populated by Map* calls without needing the routing middleware.
        var routeBuilder = (IEndpointRouteBuilder)app;
        var endpoints = routeBuilder.DataSources.SelectMany(s => s.Endpoints).ToList();
        return Assert.Single(endpoints);
    }

    private sealed class ConstructorThrowsTransformer : IRawTransformer
    {
        public ConstructorThrowsTransformer()
            => throw new InvalidOperationException("transformer must not be constructed at startup");

        public void ModifyRequest(System.Net.Http.HttpRequestMessage request, TransformerContext context) { }
        public void ModifyResponseHeaders(System.Net.Http.Headers.HttpResponseHeaders headers, TransformerContext context) { }
    }

    [RequiresAuthentication]
    private sealed class AuthRequiredTransformer : RawForwardTransformer
    {
    }
}
