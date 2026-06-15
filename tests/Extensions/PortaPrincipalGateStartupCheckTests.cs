using System.Text.Encodings.Web;

using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// Verifies the startup guard that warns when a Porta endpoint requires an authenticated principal
/// but no ASP.NET Core authentication scheme is registered to populate <c>HttpContext.User</c>.
/// </summary>
public sealed class PortaPrincipalGateStartupCheckTests
{
    private const int NoSchemeEventId = 14700;

    [Fact]
    public async Task Warns_WhenEndpointRequiresPrincipal_ButNoSchemeRegistered()
    {
        var logger = new CapturingLogger<PortaPrincipalGateStartupCheck>();
        var sut = new PortaPrincipalGateStartupCheck(
            logger,
            BuildServices(requiresPrincipal: true, withScheme: false));

        await sut.StartAsync(TestContext.Current.CancellationToken);

        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Critical && e.Id.Id == NoSchemeEventId);
    }

    [Fact]
    public async Task Silent_WhenEndpointRequiresPrincipal_AndSchemeRegistered()
    {
        var logger = new CapturingLogger<PortaPrincipalGateStartupCheck>();
        var sut = new PortaPrincipalGateStartupCheck(
            logger,
            BuildServices(requiresPrincipal: true, withScheme: true));

        await sut.StartAsync(TestContext.Current.CancellationToken);

        Assert.DoesNotContain(logger.Entries, e => e.Id.Id == NoSchemeEventId);
    }

    [Fact]
    public async Task Silent_WhenOnlyAnonymousEndpoints_AndNoScheme()
    {
        // Precision: an AllowAnonymous Porta endpoint stamps "does not require a principal", so the
        // legitimate "AddPortaCore + AllowAnonymous, no scheme" shape must not be flagged.
        var logger = new CapturingLogger<PortaPrincipalGateStartupCheck>();
        var sut = new PortaPrincipalGateStartupCheck(
            logger,
            BuildServices(requiresPrincipal: false, withScheme: false));

        await sut.StartAsync(TestContext.Current.CancellationToken);

        Assert.DoesNotContain(logger.Entries, e => e.Id.Id == NoSchemeEventId);
    }

    private static IServiceProvider BuildServices(bool requiresPrincipal, bool withScheme)
    {
        var endpoint = new Endpoint(
            _ => Task.CompletedTask,
            new EndpointMetadataCollection(new PortaPrincipalRequirementMetadata(requiresPrincipal)),
            "test-endpoint");

        var services = new ServiceCollection();
        services.AddSingleton<EndpointDataSource>(new FakeEndpointDataSource([endpoint]));
        if (withScheme)
        {
            services.AddAuthentication("Test")
                .AddScheme<AuthenticationSchemeOptions, NoopHandler>("Test", _ => { });
            services.AddLogging();
        }

        return services.BuildServiceProvider();
    }

    private sealed class FakeEndpointDataSource(IReadOnlyList<Endpoint> endpoints) : EndpointDataSource
    {
        public override IReadOnlyList<Endpoint> Endpoints { get; } = endpoints;
        public override IChangeToken GetChangeToken() => new CancellationChangeToken(CancellationToken.None);
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, EventId Id)> Entries { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Entries.Add((logLevel, eventId));

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }

    private sealed class NoopHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());
    }
}
