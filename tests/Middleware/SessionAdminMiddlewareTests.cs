using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;

using b17s.Porta.Auth.Sessions;
using b17s.Porta.Middleware;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Middleware;

/// <summary>
/// End-to-end tests for SessionAdminMiddleware covering:
///  - P0-5: every endpoint must require an authenticated caller satisfying the admin
///    policy. There is no per-user "self" mode that lets a regular user act on their
///    own (or anyone else's) sessions.
///  - P0-6: path matching must respect segment boundaries. The original implementation
///    used a naive StartsWith, so a request to /bff/admin/sessions-fake would land
///    inside the admin branch.
/// </summary>
public sealed class SessionAdminMiddlewareTests
{
    private const string AdminPolicy = "AdminOnly";

    [Fact]
    public async Task Unauthenticated_Returns401_AndDoesNotCallSessionService()
    {
        var sessions = new RecordingSessionManagement();
        using var host = await CreateHostAsync(sessions, authenticatedAs: null);
        var client = host.GetTestServer().CreateClient();

        var response = await client.GetAsync(
            "/bff/admin/sessions?email=victim@example.com",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, sessions.GetByEmailCallCount);
    }

    [Fact]
    public async Task NonAdminUser_Returns403_EvenForOwnEmail()
    {
        // Regression for P0-5: there is no "I'm acting on my own sessions" carve-out.
        // A regular authenticated user must be rejected by the admin policy regardless
        // of whether the email in the query matches their own.
        var sessions = new RecordingSessionManagement();
        using var host = await CreateHostAsync(
            sessions,
            authenticatedAs: new AuthenticatedUser("user-1", "user@example.com", IsAdmin: false));
        var client = host.GetTestServer().CreateClient();

        var response = await client.GetAsync(
            "/bff/admin/sessions?email=user@example.com",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, sessions.GetByEmailCallCount);
    }

    [Fact]
    public async Task NonAdminUser_CannotDeleteOtherUserSession()
    {
        // The DELETE-by-sessionId endpoint also requires admin - there is no
        // "I own this session" shortcut.
        var sessions = new RecordingSessionManagement();
        using var host = await CreateHostAsync(
            sessions,
            authenticatedAs: new AuthenticatedUser("user-1", "user@example.com", IsAdmin: false));
        var client = host.GetTestServer().CreateClient();

        var response = await client.DeleteAsync(
            "/bff/admin/sessions/some-session-id",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, sessions.TerminateBySessionIdCallCount);
    }

    [Fact]
    public async Task Admin_CanListSessionsByEmail()
    {
        var sessions = new RecordingSessionManagement();
        using var host = await CreateHostAsync(
            sessions,
            authenticatedAs: new AuthenticatedUser("admin-1", "admin@example.com", IsAdmin: true));
        var client = host.GetTestServer().CreateClient();

        var response = await client.GetAsync(
            "/bff/admin/sessions?email=user@example.com",
            TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal(1, sessions.GetByEmailCallCount);
        Assert.Equal("user@example.com", sessions.LastQueriedEmail);
    }

    [Fact]
    public async Task PrefixCollision_DoesNotEnterAdminBranch()
    {
        // Regression for P0-6: a request to /bff/admin/sessions-fake (note: hyphen,
        // not slash) shares the literal prefix "/bff/admin/sessions" but is NOT inside
        // the admin path. The middleware must use segment-aware matching so this falls
        // through to the next handler instead of getting captured (and returning 401/403).
        var sessions = new RecordingSessionManagement();
        using var host = await CreateHostAsync(sessions, authenticatedAs: null);
        var client = host.GetTestServer().CreateClient();

        var response = await client.GetAsync(
            "/bff/admin/sessions-fake?email=user@example.com",
            TestContext.Current.CancellationToken);

        // The fall-through handler returns 418 so we can prove the request bypassed
        // the admin middleware entirely (rather than just happening to return 200).
        Assert.Equal((HttpStatusCode)418, response.StatusCode);
        Assert.Equal(0, sessions.GetByEmailCallCount);
    }

    [Fact]
    public async Task DeleteSession_DefaultsToRevokeTokensFalse_WhenQueryAbsent()
    {
        // The previous parser returned true unless the value was literally "false",
        // making token revocation the default for an unrelated query (or no value).
        // The fixed parser requires an explicit `?revokeTokens=true` to revoke.
        var sessions = new RecordingSessionManagement();
        using var host = await CreateHostAsync(
            sessions,
            authenticatedAs: new AuthenticatedUser("admin-1", "admin@example.com", IsAdmin: true));
        var client = host.GetTestServer().CreateClient();

        var response = await client.DeleteAsync(
            "/bff/admin/sessions/sid-1",
            TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal(1, sessions.TerminateBySessionIdCallCount);
        Assert.False(sessions.LastRevokeTokens);
    }

    [Fact]
    public async Task DeleteSession_RevokesTokens_WhenExplicitlyRequested()
    {
        var sessions = new RecordingSessionManagement();
        using var host = await CreateHostAsync(
            sessions,
            authenticatedAs: new AuthenticatedUser("admin-1", "admin@example.com", IsAdmin: true));
        var client = host.GetTestServer().CreateClient();

        var response = await client.DeleteAsync(
            "/bff/admin/sessions/sid-1?revokeTokens=true",
            TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.True(sessions.LastRevokeTokens);
    }

    [Fact]
    public async Task DeleteSession_LogsRedactedSessionId_NotRaw()
    {
        // SECURITY: a session id is Secret-classified (it addresses the server-side auth
        // ticket). The admin audit log must record a non-reversible fingerprint, never the
        // raw id - matching every other session-id log path.
        const string rawSessionId = "raw-secret-session-id-123";
        var capture = new CapturingLoggerProvider();
        var sessions = new RecordingSessionManagement();
        using var host = await CreateHostAsync(
            sessions,
            authenticatedAs: new AuthenticatedUser("admin-1", "admin@example.com", IsAdmin: true),
            loggerProvider: capture);
        var client = host.GetTestServer().CreateClient();

        var response = await client.DeleteAsync(
            $"/bff/admin/sessions/{rawSessionId}",
            TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();

        // Scope to Porta's own log statements: the raw id unavoidably appears in the framework's
        // request-path log because it is a URL segment, which is outside Porta's control. The fix
        // governs Porta's audit statements, which must never emit the raw id.
        var portaMessages = capture.Messages
            .Where(m => m.Category.StartsWith("b17s.Porta", StringComparison.Ordinal))
            .Select(m => m.Message)
            .ToArray();

        Assert.NotEmpty(portaMessages);
        Assert.DoesNotContain(portaMessages, m => m.Contains(rawSessionId, StringComparison.Ordinal));
        // The redacted fingerprint must appear in the audit trail so operators can still correlate.
        var expectedRedacted = LogRedaction.RedactSessionId(rawSessionId);
        Assert.Contains(portaMessages, m => m.Contains(expectedRedacted, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ExactPath_StillEntersAdminBranch()
    {
        // Sanity check: the segment-aware matching must not break the legitimate case.
        var sessions = new RecordingSessionManagement();
        using var host = await CreateHostAsync(
            sessions,
            authenticatedAs: new AuthenticatedUser("admin-1", "admin@example.com", IsAdmin: true));
        var client = host.GetTestServer().CreateClient();

        var response = await client.GetAsync(
            "/bff/admin/sessions?email=user@example.com",
            TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
    }

    private static async Task<IHost> CreateHostAsync(
        ISessionManagementService sessionManagement,
        AuthenticatedUser? authenticatedAs,
        ILoggerProvider? loggerProvider = null)
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    if (loggerProvider is not null)
                    {
                        services.AddLogging(b => b.AddProvider(loggerProvider));
                    }
                    services.AddSingleton(sessionManagement);
                    services.AddOptions<SessionAdminOptions>()
                        .Configure(o => o.RequirePolicy = AdminPolicy);

                    services.AddAuthentication(StubAuthHandler.SchemeName)
                        .AddScheme<StubAuthSchemeOptions, StubAuthHandler>(
                            StubAuthHandler.SchemeName,
                            options => options.User = authenticatedAs);
                    services.AddAuthorization(options =>
                    {
                        options.AddPolicy(AdminPolicy, p => p.RequireClaim(ClaimTypes.Role, "Admin"));
                    });
                });
                webHost.Configure(app =>
                {
                    app.UseAuthentication();
                    // Mount the admin middleware directly so we exercise its own
                    // path matching and EnforceAdminAsync logic, not just the outer
                    // UseSessionAdmin branch's authorization wrapper.
                    app.UseMiddleware<SessionAdminMiddleware>();

                    // Fall-through handler that proves a request bypassed the admin branch.
                    app.Run(async context =>
                    {
                        context.Response.StatusCode = 418;
                        await context.Response.WriteAsync("teapot");
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    private sealed record AuthenticatedUser(string Sub, string Email, bool IsAdmin);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<(string Category, string Message)> _messages = new();

        public IReadOnlyList<(string Category, string Message)> Messages => _messages.ToArray();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _messages);

        public void Dispose() { }

        private sealed class CapturingLogger(string category, System.Collections.Concurrent.ConcurrentQueue<(string, string)> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
                => messages.Enqueue((category, formatter(state, exception)));
        }
    }

    private sealed class StubAuthSchemeOptions : AuthenticationSchemeOptions
    {
        public AuthenticatedUser? User { get; set; }
    }

    private sealed class StubAuthHandler(
        IOptionsMonitor<StubAuthSchemeOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder) : AuthenticationHandler<StubAuthSchemeOptions>(options, loggerFactory, encoder)
    {
        public const string SchemeName = "Stub";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var user = Options.User;
            if (user is null)
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }
            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, user.Sub),
                new("sub", user.Sub),
                new(ClaimTypes.Email, user.Email),
            };
            if (user.IsAdmin)
            {
                claims.Add(new Claim(ClaimTypes.Role, "Admin"));
            }
            var identity = new ClaimsIdentity(claims, SchemeName);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, SchemeName);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }

    private sealed class RecordingSessionManagement : ISessionManagementService
    {
        public int GetByEmailCallCount { get; private set; }
        public string? LastQueriedEmail { get; private set; }
        public int TerminateByEmailCallCount { get; private set; }
        public int TerminateBySessionIdCallCount { get; private set; }
        public bool? LastRevokeTokens { get; private set; }
        public string? LastReason { get; private set; }

        public Task<IReadOnlyList<SessionInfo>> GetSessionsByEmailAsync(string email, CancellationToken cancellationToken = default)
        {
            GetByEmailCallCount++;
            LastQueriedEmail = email;
            return Task.FromResult<IReadOnlyList<SessionInfo>>([]);
        }

        public Task<int> TerminateSessionsByEmailAsync(string email, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified")
        {
            TerminateByEmailCallCount++;
            LastRevokeTokens = revokeTokens;
            LastReason = reason;
            return Task.FromResult(0);
        }

        public Task<bool> TerminateSessionAsync(string sessionId, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified")
        {
            TerminateBySessionIdCallCount++;
            LastRevokeTokens = revokeTokens;
            LastReason = reason;
            return Task.FromResult(true);
        }

        public Task RegisterSessionAsync(string sessionId, string userId, string? email = null, string? ipAddress = null, string? userAgent = null, string? encryptedRefreshToken = null) => Task.CompletedTask;
        public Task UpdateRefreshTokenAsync(string sessionId, string? encryptedRefreshToken) => Task.CompletedTask;
        public string? ProtectRefreshToken(string? refreshToken) => refreshToken;
        public Task<int> TerminateSessionsBySubjectAsync(string subject, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified") => Task.FromResult(0);
        public Task TouchSessionAsync(string sessionId) => Task.CompletedTask;
    }
}
