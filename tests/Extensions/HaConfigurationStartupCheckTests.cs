using System.Collections.Concurrent;
using System.Xml.Linq;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Extensions;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using HaCheck = b17s.Porta.Extensions.HaConfigurationStartupCheck;

namespace b17s.Porta.Tests.Extensions;

public class HaConfigurationStartupCheckTests
{
    [Fact]
    public async Task Production_PersistenceWithoutEncryption_ThrowsOnStartup()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddPortaDataProtectionPersistence(
            persist: dp => dp.PersistKeysToFileSystem(new DirectoryInfo(Path.GetTempPath())),
            protectKeys: null);

        AddPortaAuthWithEnv(services, Environments.Production);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await Assert.ThrowsAsync<InvalidOperationException>(() => hosted.StartAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Production_PersistenceWithProtectKeys_DoesNotThrow()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddPortaDataProtectionPersistence(
            persist: dp => dp.PersistKeysToFileSystem(new DirectoryInfo(Path.GetTempPath())),
            // A protectKeys action that genuinely registers an IXmlEncryptor - mirrors what
            // a real ProtectKeysWith… extension does. The hollow (empty-lambda) case is
            // covered by Production_PersistenceWithHollowProtectKeys_ThrowsOnStartup.
            protectKeys: dp => dp.Services.Configure<KeyManagementOptions>(
                o => o.XmlEncryptor = new FakeXmlEncryptor()));

        AddPortaAuthWithEnv(services, Environments.Production);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Production_PersistenceWithHollowProtectKeys_ThrowsOnStartup()
    {
        // A protectKeys action was supplied (attestation present) but it never registered
        // an IXmlEncryptor, so keys still persist in plaintext. The startup check must catch
        // this once the effective KeyManagementOptions are bound, not trust the marker alone.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddPortaDataProtectionPersistence(
            persist: dp => dp.PersistKeysToFileSystem(new DirectoryInfo(Path.GetTempPath())),
            protectKeys: _ => { /* hollow attestation - registers no encryptor */ });

        AddPortaAuthWithEnv(services, Environments.Production);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await Assert.ThrowsAsync<InvalidOperationException>(() => hosted.StartAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Development_PersistenceWithHollowProtectKeys_LogsWarningAndDoesNotThrow()
    {
        var capture = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(capture).SetMinimumLevel(LogLevel.Trace));
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddPortaDataProtectionPersistence(
            persist: dp => dp.PersistKeysToFileSystem(new DirectoryInfo(Path.GetTempPath())),
            protectKeys: _ => { /* hollow attestation - registers no encryptor */ });

        AddPortaAuthWithEnv(services, Environments.Development);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);

        Assert.Contains(capture.Entries, e => e.EventId.Id == 14506);
        Assert.DoesNotContain(capture.Entries, e => e.EventId.Id == 14507);
    }

    [Fact]
    public async Task Production_PersistenceWithAcknowledgement_DoesNotThrow()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddPortaDataProtectionPersistence(
            persist: dp => dp.PersistKeysToFileSystem(new DirectoryInfo(Path.GetTempPath())),
            protectKeys: null);
        services.AcknowledgeUnencryptedDataProtectionKeys(reason: "test single-box");

        AddPortaAuthWithEnv(services, Environments.Production);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Development_PersistenceWithoutEncryption_LogsWarningAndDoesNotThrow()
    {
        var capture = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(capture).SetMinimumLevel(LogLevel.Trace));
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddPortaDataProtectionPersistence(
            persist: dp => dp.PersistKeysToFileSystem(new DirectoryInfo(Path.GetTempPath())),
            protectKeys: null);

        AddPortaAuthWithEnv(services, Environments.Development);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);

        Assert.Contains(capture.Entries, e => e.EventId.Id == 14502);
        Assert.DoesNotContain(capture.Entries, e => e.EventId.Id == 14503);
    }

    [Fact]
    public async Task NoPersistenceAtAll_DoesNotTriggerEncryptionThrow()
    {
        var capture = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(capture).SetMinimumLevel(LogLevel.Trace));

        AddPortaAuthWithEnv(services, Environments.Production);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);

        // The persistence-missing warning fires (existing behavior). The encryption-fatal
        // path is gated on persistence being configured, so it must NOT fire here even
        // though we're in Production with no protectKeys.
        Assert.Contains(capture.Entries, e => e.EventId.Id == 14501);
        Assert.DoesNotContain(capture.Entries, e => e.EventId.Id == 14503);
        Assert.DoesNotContain(capture.Entries, e => e.EventId.Id == 14502);
    }

    [Fact]
    public void EfHelper_RejectsNullProtectKeys()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() =>
            services.AddPortaDataProtectionWithEntityFrameworkStore(
                _ => { /* options not exercised - null check happens first */ },
                protectKeys: null!));
    }

    [Fact]
    public void EfHelper_RejectsNullOptionsAction()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() =>
            services.AddPortaDataProtectionWithEntityFrameworkStore(
                optionsAction: null!,
                protectKeys: _ => { }));
    }

    [Fact]
    public void OpenHook_RejectsNullPersist()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() =>
            services.AddPortaDataProtectionPersistence(persist: null!, protectKeys: null));
    }

    [Fact]
    public void Acknowledgement_RejectsNullReason()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() =>
            services.AcknowledgeUnencryptedDataProtectionKeys(reason: null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Acknowledgement_RejectsBlankReason(string reason)
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentException>(() =>
            services.AcknowledgeUnencryptedDataProtectionKeys(reason));
    }

    [Fact]
    public async Task EndToEnd_AddBffAuthentication_ProductionWithoutDpEncryption_ThrowsOnHostedStart()
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
        var config = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddSingleton<IHostEnvironment>(new TestHostEnvironment(Environments.Production));
        services.AddPortaDataProtectionPersistence(
            persist: dp => dp.PersistKeysToFileSystem(new DirectoryInfo(Path.GetTempPath())),
            protectKeys: null);
        services.AddPortaAuthentication(config);

        var sp = services.BuildServiceProvider();
        var hosted = sp.GetServices<IHostedService>().OfType<HaCheck>().Single();

        await Assert.ThrowsAsync<InvalidOperationException>(() => hosted.StartAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Production_DistributedCache_NoConsumerLock_AutoPicksDistributedLock_NoThrow()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());

        AddPortaAuthWithEnv(services, Environments.Production);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);
        await hosted.StartAsync(CancellationToken.None);

        var lockImpl = sp.GetRequiredService<IRefreshLock>();
        Assert.IsType<DistributedCacheRefreshLock>(lockImpl);
    }

    [Fact]
    public async Task Production_NoDistributedCache_AutoPicksInProcessLock_NoThrow()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        AddPortaAuthWithEnv(services, Environments.Production);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);
        await hosted.StartAsync(CancellationToken.None);

        var lockImpl = sp.GetRequiredService<IRefreshLock>();
        Assert.IsType<RefreshLockRegistry>(lockImpl);
    }

    [Fact]
    public async Task Production_DistributedCache_ConsumerExplicitlyRegistersInProcessLock_Throws()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddSingleton<IRefreshLock, RefreshLockRegistry>();

        AddPortaAuthWithEnv(services, Environments.Production);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await Assert.ThrowsAsync<InvalidOperationException>(() => hosted.StartAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Production_DistributedCache_ConsumerInProcessLockWithAcknowledgement_DoesNotThrow()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddSingleton<IRefreshLock, RefreshLockRegistry>();
        services.AcknowledgeInProcessRefreshLock(reason: "single-box, redis cache only used for IDistributedCache");

        AddPortaAuthWithEnv(services, Environments.Production);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Development_DistributedCache_ConsumerInProcessLock_LogsWarningAndDoesNotThrow()
    {
        var capture = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(capture).SetMinimumLevel(LogLevel.Trace));
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddSingleton<IRefreshLock, RefreshLockRegistry>();

        AddPortaAuthWithEnv(services, Environments.Development);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);
        await hosted.StartAsync(CancellationToken.None);

        Assert.Contains(capture.Entries, e => e.EventId.Id == 14504);
        Assert.DoesNotContain(capture.Entries, e => e.EventId.Id == 14505);
    }

    [Fact]
    public async Task Production_DistributedCache_ConsumerCustomLock_DoesNotThrow()
    {
        // A consumer-provided non-RefreshLockRegistry implementation is trusted.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDistributedCache>(new NoopDistributedCache());
        services.AddSingleton<IRefreshLock, FakeDistributedRefreshLock>();

        AddPortaAuthWithEnv(services, Environments.Production);

        var sp = services.BuildServiceProvider();
        var hosted = ResolveStartupCheck(sp);

        await hosted.StartAsync(CancellationToken.None);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void InProcessRefreshLockAcknowledgement_RejectsBlankReason(string reason)
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentException>(() =>
            services.AcknowledgeInProcessRefreshLock(reason));
    }

    [Fact]
    public void InProcessRefreshLockAcknowledgement_RejectsNullReason()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() =>
            services.AcknowledgeInProcessRefreshLock(reason: null!));
    }

    // Stands in for what a real ProtectKeysWith… extension registers: an IXmlEncryptor on
    // KeyManagementOptions. Its Encrypt is never invoked by the startup check (which only
    // inspects whether the encryptor is present), so a minimal pass-through body suffices.
    private sealed class FakeXmlEncryptor : IXmlEncryptor
    {
        public EncryptedXmlInfo Encrypt(XElement plaintextElement) =>
            new(plaintextElement, typeof(FakeXmlDecryptor));
    }

    private sealed class FakeXmlDecryptor : IXmlDecryptor
    {
        public XElement Decrypt(XElement encryptedElement) => encryptedElement;
    }

    private sealed class FakeDistributedRefreshLock : IRefreshLock
    {
        public Task<RefreshLockHandle> AcquireAsync(string lockKey, TimeSpan timeout, CancellationToken cancellationToken = default) =>
            Task.FromResult(new RefreshLockHandle(true));
    }

    private static void AddPortaAuthWithEnv(IServiceCollection services, string envName)
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
        var config = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();

        services.AddSingleton<IHostEnvironment>(new TestHostEnvironment(envName));
        services.AddPortaAuthentication(config);
    }

    private static HaCheck ResolveStartupCheck(IServiceProvider sp) =>
        sp.GetServices<IHostedService>().OfType<HaCheck>().Single();

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

    private sealed class NoopDistributedCache : IDistributedCache
    {
        public byte[]? Get(string key) => null;
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult<byte[]?>(null);
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) { }
        public Task RemoveAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) { }
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => Task.CompletedTask;
    }
}
