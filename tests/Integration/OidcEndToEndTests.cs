using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Integration;

/// <summary>
/// Boots the full BFF auth pipeline against <see cref="FakeIdp"/> and exercises
/// the OIDC code flow end-to-end. The framework OIDC handler does the actual
/// state/nonce/PKCE/code-exchange/id_token validation; this test verifies that
/// our DI wiring + RegisterSessionAsync hook + token revocation all hang
/// together correctly.
/// </summary>
public sealed class OidcEndToEndTests : IDisposable
{
    private readonly FakeIdp _idp;

    public OidcEndToEndTests()
    {
        _idp = new FakeIdp("https://idp.test");
    }

    public void Dispose() => _idp.Dispose();

    [Fact]
    public async Task Login_RedirectsToFakeIdpAuthorize()
    {
        using var bff = await CreateBffAsync();
        var client = bff.CreateAuthenticatedClient();

        var response = await client.GetAsync("/bff/login", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.Equal("idp.test", location.Host);
        Assert.Equal("/authorize", location.AbsolutePath);
        Assert.Contains("code_challenge=", location.Query);
        Assert.Contains("state=", location.Query);
        Assert.Contains("nonce=", location.Query);
    }

    [Fact]
    public async Task FullLoginFlow_SetsCookie_AndRegistersSession()
    {
        var recorder = new RegistrationRecorder();
        using var bff = await CreateBffAsync(recorder);

        _ = await bff.LoginAsync(_idp, TestContext.Current.CancellationToken);

        // RegisterSessionAsync was called with a real encrypted refresh token.
        Assert.Equal(1, recorder.Calls);
        Assert.Equal("user@example.com", recorder.LastEmail);
        Assert.Equal("user-1", recorder.LastUserId);
        Assert.False(string.IsNullOrEmpty(recorder.LastEncryptedRefreshToken));
    }

    [Fact]
    public async Task FullLoginFlow_EmailNotVerified_RegistersSessionWithoutEmail()
    {
        // Regression for P1-7: when the IdP doesn't assert email_verified=true, the
        // BFF must not index the session by email - an unverified user could otherwise
        // squat on another user's address. Sub-keyed registration must still happen.
        var identity = new System.Security.Claims.ClaimsIdentity(authenticationType: "fake-idp");
        identity.AddClaim(new System.Security.Claims.Claim("sub", "user-1"));
        identity.AddClaim(new System.Security.Claims.Claim("email", "user@example.com"));
        identity.AddClaim(new System.Security.Claims.Claim("email_verified", "false", System.Security.Claims.ClaimValueTypes.Boolean));
        identity.AddClaim(new System.Security.Claims.Claim("name", "Test User"));
        _idp.NextUserIdentity = identity;

        var recorder = new RegistrationRecorder();
        using var bff = await CreateBffAsync(recorder);

        _ = await bff.LoginAsync(_idp, TestContext.Current.CancellationToken);

        Assert.Equal(1, recorder.Calls);
        Assert.Null(recorder.LastEmail);
        Assert.Equal("user-1", recorder.LastUserId);
    }

    [Fact]
    public async Task FullLoginFlow_NoEmailClaim_RegistersSessionWithoutEmail()
    {
        // Regression for P1-7: previously, an absent `email` claim caused the BFF to
        // fall back to `preferred_username` - which is neither unique nor verified per
        // OIDC §5.7. The fix drops the fallback entirely; sub-only registration is fine.
        var identity = new System.Security.Claims.ClaimsIdentity(authenticationType: "fake-idp");
        identity.AddClaim(new System.Security.Claims.Claim("sub", "user-1"));
        identity.AddClaim(new System.Security.Claims.Claim("preferred_username", "testuser"));
        _idp.NextUserIdentity = identity;

        var recorder = new RegistrationRecorder();
        using var bff = await CreateBffAsync(recorder);

        _ = await bff.LoginAsync(_idp, TestContext.Current.CancellationToken);

        Assert.Equal(1, recorder.Calls);
        Assert.Null(recorder.LastEmail);
        Assert.Equal("user-1", recorder.LastUserId);
    }

    private Task<IHost> CreateBffAsync(RegistrationRecorder? recorder = null)
    {
        var host = new PortaTestHost().WithFakeIdp(_idp);
        if (recorder is not null)
        {
            host.ConfigureServices(services =>
            {
                services.AddSingleton(recorder);
                services.AddScoped<ISessionManagementService>(sp =>
                    new RecordingSessionManagementService(
                        new SessionManagementService(
                            sp.GetRequiredService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>(),
                            sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<b17s.Porta.Configuration.SessionAuthenticationConfiguration>>(),
                            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<SessionManagementService>>(),
                            tokenRevocationService: sp.GetRequiredService<ITokenRevocationService>(),
                            dataProtectionProvider: sp.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>()),
                        recorder));
            });
        }
        return host.StartAsync();
    }

    private sealed class RegistrationRecorder
    {
        public int Calls { get; set; }
        public string? LastEmail { get; set; }
        public string? LastUserId { get; set; }
        public string? LastEncryptedRefreshToken { get; set; }
    }

    private sealed class RecordingSessionManagementService(SessionManagementService inner, RegistrationRecorder recorder) : ISessionManagementService
    {
        public Task RegisterSessionAsync(string sessionId, string userId, string? email = null, string? ipAddress = null, string? userAgent = null, string? encryptedRefreshToken = null)
        {
            recorder.Calls++;
            recorder.LastEmail = email;
            recorder.LastUserId = userId;
            recorder.LastEncryptedRefreshToken = encryptedRefreshToken;
            return inner.RegisterSessionAsync(sessionId, userId, email, ipAddress, userAgent, encryptedRefreshToken);
        }

        public Task UpdateRefreshTokenAsync(string sessionId, string? encryptedRefreshToken)
            => inner.UpdateRefreshTokenAsync(sessionId, encryptedRefreshToken);
        public string? ProtectRefreshToken(string? refreshToken)
            => inner.ProtectRefreshToken(refreshToken);
        public Task<IReadOnlyList<SessionInfo>> GetSessionsByEmailAsync(string email, CancellationToken cancellationToken = default)
            => inner.GetSessionsByEmailAsync(email, cancellationToken);
        public Task<bool> TerminateSessionAsync(string sessionId, bool revokeTokens = true, CancellationToken cancellationToken = default)
            => inner.TerminateSessionAsync(sessionId, revokeTokens, cancellationToken);
        public Task<int> TerminateSessionsByEmailAsync(string email, bool revokeTokens = true, CancellationToken cancellationToken = default)
            => inner.TerminateSessionsByEmailAsync(email, revokeTokens, cancellationToken);
        public Task<int> TerminateSessionsBySubjectAsync(string subject, bool revokeTokens = true, CancellationToken cancellationToken = default)
            => inner.TerminateSessionsBySubjectAsync(subject, revokeTokens, cancellationToken);
        public Task TouchSessionAsync(string sessionId)
            => inner.TouchSessionAsync(sessionId);
    }
}
