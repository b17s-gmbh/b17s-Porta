using System.Collections.Concurrent;

using b17s.Porta.Extensions;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using CookieCheck = b17s.Porta.Extensions.CookieSecurityStartupCheck;

namespace b17s.Porta.Tests.Extensions;

public class CookieSecurityStartupCheckTests
{
    [Fact]
    public async Task Production_SecureDefaults_DoesNotThrowOrWarn()
    {
        var capture = new CapturingLoggerProvider();
        var services = BuildServices(capture, Environments.Production, overrides: null);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);

        Assert.DoesNotContain(capture.Entries, e => e.EventId.Id is 14700 or 14701 or 14702 or 14703 or 14704);
    }

    [Fact]
    public async Task EffectiveCookieLifetimeExceedingRevocationIndexTtl_LogsWarning()
    {
        // Post-configuring CookieAuthenticationOptions directly bypasses the
        // config-derived revocation-index TTL (max(SessionTimeoutInMin,
        // Cookie.ExpireTimeSpanMinutes)) - the only remaining way to reopen the
        // H1 gap where the sub/email indexes expire before the cookie does.
        var capture = new CapturingLoggerProvider();
        var services = BuildServices(capture, Environments.Production, overrides: null);
        services.PostConfigure<CookieAuthenticationOptions>(
            CookieAuthenticationDefaults.AuthenticationScheme,
            o => o.ExpireTimeSpan = TimeSpan.FromHours(24));

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);

        Assert.Contains(capture.Entries, e => e.EventId.Id == 14704 && e.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task ConfigDrivenCookieLifetimeLongerThanSessionTimeout_DoesNotWarn()
    {
        // Config-driven wiring derives the index TTL as max(SessionTimeoutInMin,
        // Cookie.ExpireTimeSpanMinutes), so a long cookie lifetime alone cannot
        // open the revocation gap and must not warn.
        var capture = new CapturingLoggerProvider();
        var services = BuildServices(
            capture,
            Environments.Production,
            overrides: new()
            {
                ["SessionAuthentication:SessionTimeoutInMin"] = "30",
                ["SessionAuthentication:Cookie:ExpireTimeSpanMinutes"] = "480",
            });

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);

        Assert.DoesNotContain(capture.Entries, e => e.EventId.Id == 14704);
    }

    [Theory]
    [InlineData("None")]
    [InlineData("SameAsRequest")]
    public async Task Production_SecurePolicyDowngrade_ThrowsOnStartup(string securePolicy)
    {
        var services = BuildServices(
            capture: null,
            Environments.Production,
            overrides: new() { ["SessionAuthentication:Cookie:SecurePolicy"] = securePolicy });

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await Assert.ThrowsAsync<InvalidOperationException>(() => hosted.StartAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Production_RequireHttpsMetadataFalse_ThrowsOnStartup()
    {
        var services = BuildServices(
            capture: null,
            Environments.Production,
            overrides: new() { ["SessionAuthentication:RequireHttpsMetadata"] = "false" });

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await Assert.ThrowsAsync<InvalidOperationException>(() => hosted.StartAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Development_SecurePolicyDowngrade_LogsWarningAndDoesNotThrow()
    {
        var capture = new CapturingLoggerProvider();
        var services = BuildServices(
            capture,
            Environments.Development,
            overrides: new() { ["SessionAuthentication:Cookie:SecurePolicy"] = "None" });

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);

        Assert.Contains(capture.Entries, e => e.EventId.Id == 14700);
        Assert.DoesNotContain(capture.Entries, e => e.EventId.Id == 14701);
    }

    [Fact]
    public async Task Development_RequireHttpsMetadataFalse_LogsWarningAndDoesNotThrow()
    {
        var capture = new CapturingLoggerProvider();
        var services = BuildServices(
            capture,
            Environments.Development,
            overrides: new() { ["SessionAuthentication:RequireHttpsMetadata"] = "false" });

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);

        Assert.Contains(capture.Entries, e => e.EventId.Id == 14702);
        Assert.DoesNotContain(capture.Entries, e => e.EventId.Id == 14703);
    }

    private static ServiceCollection BuildServices(
        CapturingLoggerProvider? capture,
        string envName,
        Dictionary<string, string?>? overrides)
    {
        var dict = new Dictionary<string, string?>
        {
            ["SessionAuthentication:Authority"] = "https://idp.example.com",
            ["SessionAuthentication:ClientId"] = "test-client",
            ["SessionAuthentication:ClientSecret"] = "test-secret",
            ["SessionAuthentication:Scope"] = "openid",
            ["SessionAuthentication:CookieName"] = "TestCookie",
            ["SessionAuthentication:UsePkce"] = "true",
            ["SessionAuthentication:SessionTimeoutInMin"] = "60",
            ["SessionAuthentication:DataProtection:ApplicationName"] = "TestApp",
            ["SessionAuthentication:DataProtection:KeyLifetimeDays"] = "30",
        };
        if (overrides is not null)
        {
            foreach (var kvp in overrides)
            {
                dict[kvp.Key] = kvp.Value;
            }
        }
        var config = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();

        var services = new ServiceCollection();
        if (capture is not null)
        {
            services.AddLogging(b => b.AddProvider(capture).SetMinimumLevel(LogLevel.Trace));
        }
        else
        {
            services.AddLogging();
        }
        services.AddSingleton<IHostEnvironment>(new TestHostEnvironment(envName));
        services.AddPortaAuthentication(config);
        return services;
    }

    private static CookieCheck ResolveStartupCheck(IServiceProvider sp) =>
        sp.GetServices<IHostedService>().OfType<CookieCheck>().Single();

    private sealed class TestHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } =
            new Microsoft.Extensions.FileProviders.NullFileProvider();
    }

    private sealed record LogEntry(LogLevel Level, EventId EventId, string Message);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentBag<LogEntry> Entries { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Entries);
        public void Dispose() { }

        private sealed class CapturingLogger(ConcurrentBag<LogEntry> sink) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                sink.Add(new LogEntry(logLevel, eventId, formatter(state, exception)));
            }
        }
    }
}
