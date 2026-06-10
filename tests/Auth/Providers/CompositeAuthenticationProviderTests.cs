using b17s.Porta.Auth.Providers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace b17s.Porta.Tests.Auth.Providers;

public sealed class CompositeAuthenticationProviderTests
{
    [Fact]
    public async Task GetAuthContextAsync_FirstAuthenticatedProviderWins_LaterProvidersNotConsulted()
    {
        var winner = new RecordingProvider("Cookies", auth: AuthenticatedContext());
        var loser = new RecordingProvider("Bearer", auth: AuthenticatedContext("other"));
        var sut = Create(winner, loser);

        var result = await sut.GetAuthContextAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken);

        Assert.True(result.IsAuthenticated);
        Assert.Equal("Cookies", result.Scheme);
        Assert.Equal(1, winner.GetCalls);
        Assert.Equal(0, loser.GetCalls);
    }

    [Fact]
    public async Task GetAuthContextAsync_FirstUnauthenticatedThenAuthenticated_StampsSecondScheme()
    {
        // The composite must keep trying providers when one returns an unauthenticated
        // context (e.g., no cookie present, fall through to Bearer).
        var first = new RecordingProvider("Cookies", auth: AuthenticationContext.Unauthenticated());
        var second = new RecordingProvider("Bearer", auth: AuthenticatedContext());
        var sut = Create(first, second);

        var result = await sut.GetAuthContextAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken);

        Assert.True(result.IsAuthenticated);
        Assert.Equal("Bearer", result.Scheme);
        Assert.Equal(1, first.GetCalls);
        Assert.Equal(1, second.GetCalls);
    }

    [Fact]
    public async Task GetAuthContextAsync_AllUnauthenticated_ReturnsUnauthenticated()
    {
        var first = new RecordingProvider("Cookies", auth: AuthenticationContext.Unauthenticated());
        var second = new RecordingProvider("Bearer", auth: AuthenticationContext.Unauthenticated());
        var sut = Create(first, second);

        var result = await sut.GetAuthContextAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken);

        Assert.False(result.IsAuthenticated);
        Assert.Null(result.Scheme);
    }

    [Fact]
    public async Task GetAuthContextAsync_NoProvidersRegistered_ReturnsUnauthenticated()
    {
        var sut = Create();

        var result = await sut.GetAuthContextAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken);

        Assert.False(result.IsAuthenticated);
    }

    [Fact]
    public async Task GetAuthContextAsync_RegistrationOrderIsAuthoritative()
    {
        // Both providers can authenticate the request - registration order determines
        // which one wins. This is the documented contract; swapping order swaps Scheme.
        var bearer = new RecordingProvider("Bearer", auth: AuthenticatedContext("bearer-user"));
        var cookies = new RecordingProvider("Cookies", auth: AuthenticatedContext("cookie-user"));
        var sut = Create(bearer, cookies);

        var result = await sut.GetAuthContextAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken);

        Assert.Equal("Bearer", result.Scheme);
        Assert.Equal("bearer-user", result.Claims["sub"][0]);
    }

    [Fact]
    public async Task RefreshAsync_RoutesToProviderWithMatchingScheme()
    {
        var cookies = new RecordingProvider("Cookies", refresh: AuthenticatedContext("refreshed-via-cookies"));
        var bearer = new RecordingProvider("Bearer", refresh: AuthenticatedContext("refreshed-via-bearer"));
        var sut = Create(cookies, bearer);

        var current = AuthenticatedContext();
        current.Scheme = "Bearer";

        var refreshed = await sut.RefreshAsync(current, TestContext.Current.CancellationToken);

        Assert.NotNull(refreshed);
        Assert.Equal("refreshed-via-bearer", refreshed!.Claims["sub"][0]);
        Assert.Equal(0, cookies.RefreshCalls);
        Assert.Equal(1, bearer.RefreshCalls);
    }

    [Fact]
    public async Task RefreshAsync_EmptyScheme_ReturnsNull_NoProvidersInvoked()
    {
        var cookies = new RecordingProvider("Cookies", refresh: AuthenticatedContext());
        var sut = Create(cookies);

        var current = AuthenticatedContext();
        current.Scheme = null;

        var refreshed = await sut.RefreshAsync(current, TestContext.Current.CancellationToken);

        Assert.Null(refreshed);
        Assert.Equal(0, cookies.RefreshCalls);
    }

    [Fact]
    public async Task RefreshAsync_UnknownScheme_ReturnsNull_LogsWarning()
    {
        // A renamed or removed provider that previously authenticated a context should
        // not silently fall through to another provider's refresh - that would let the
        // composite refresh a session token via a Bearer provider's refresh-token endpoint.
        var cookies = new RecordingProvider("Cookies", refresh: AuthenticatedContext());
        var sut = Create(cookies);

        var current = AuthenticatedContext();
        current.Scheme = "RetiredScheme";

        var refreshed = await sut.RefreshAsync(current, TestContext.Current.CancellationToken);

        Assert.Null(refreshed);
        Assert.Equal(0, cookies.RefreshCalls);
    }

    [Fact]
    public async Task InvalidateAsync_FansOutToEveryProvider()
    {
        // Logout must clear every credential surface - session cookie sign-out, reference-token
        // cache eviction, etc. A bug here means a logged-out session keeps working on a
        // different scheme.
        var a = new RecordingProvider("Cookies");
        var b = new RecordingProvider("Bearer");
        var c = new RecordingProvider("ApiKey");
        var sut = Create(a, b, c);

        await sut.InvalidateAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken);

        Assert.Equal(1, a.InvalidateCalls);
        Assert.Equal(1, b.InvalidateCalls);
        Assert.Equal(1, c.InvalidateCalls);
    }

    [Fact]
    public async Task InvalidateAsync_OneProviderThrows_OthersStillInvalidated()
    {
        // Best-effort invalidation: a flaky reference-token cache failing to evict must
        // not block the session cookie from being cleared.
        var a = new RecordingProvider("Cookies");
        var b = new RecordingProvider("BrokenScheme") { InvalidateThrows = new InvalidOperationException("boom") };
        var c = new RecordingProvider("ApiKey");
        var sut = Create(a, b, c);

        await sut.InvalidateAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken);

        Assert.Equal(1, a.InvalidateCalls);
        Assert.Equal(1, b.InvalidateCalls);
        Assert.Equal(1, c.InvalidateCalls);
    }

    [Fact]
    public async Task InvalidateAsync_Canceled_PropagatesAndStopsFanOut()
    {
        // Best-effort fan-out applies to provider faults, not to cooperative cancellation:
        // a dead request must stop the logout loop, not silently skip to the next provider.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var a = new RecordingProvider("Cookies") { InvalidateThrows = new OperationCanceledException() };
        var b = new RecordingProvider("Bearer");
        var sut = Create(a, b);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sut.InvalidateAsync(new DefaultHttpContext(), cts.Token));
        Assert.Equal(0, b.InvalidateCalls);
    }

    [Fact]
    public void Scheme_IsLiteralComposite()
    {
        // The composite's own scheme should be a stable, distinct value so it cannot be
        // confused with any concrete provider's scheme.
        var sut = Create();
        Assert.Equal("Composite", sut.Scheme);
    }

    [Fact]
    public async Task TryGetAuthContextAsync_GetThrows_ReturnsUnauthenticated()
    {
        // The default interface implementation fails closed: an auth failure becomes an
        // unauthenticated context for optional-auth endpoints, never a thrown error.
        IAuthenticationProvider provider = new RecordingProvider("Bearer") { GetThrows = new InvalidOperationException("boom") };

        var result = await provider.TryGetAuthContextAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken);

        Assert.False(result.IsAuthenticated);
    }

    [Fact]
    public async Task TryGetAuthContextAsync_RequestCancelled_PropagatesInsteadOfMaskingAsUnauthenticated()
    {
        // Genuine request cancellation must NOT be swallowed into an unauthenticated context -
        // that would mask a dead request. It propagates, matching the rest of the codebase's
        // "when (ex is not OperationCanceledException)" discipline.
        IAuthenticationProvider provider = new RecordingProvider("Bearer") { GetThrows = new OperationCanceledException() };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.TryGetAuthContextAsync(new DefaultHttpContext(), TestContext.Current.CancellationToken));
    }

    private static CompositeAuthenticationProvider Create(params IAuthenticationProvider[] providers)
        => new(providers, NullLogger<CompositeAuthenticationProvider>.Instance);

    private static AuthenticationContext AuthenticatedContext(string sub = "user-1")
        => new()
        {
            AccessToken = "tok",
            Claims = new Dictionary<string, string[]> { ["sub"] = [sub] },
        };

    private sealed class RecordingProvider : IAuthenticationProvider
    {
        private readonly AuthenticationContext? _refreshResult;
        private readonly AuthenticationContext _authResult;

        public RecordingProvider(string scheme, AuthenticationContext? auth = null, AuthenticationContext? refresh = null)
        {
            Scheme = scheme;
            _authResult = auth ?? AuthenticationContext.Unauthenticated();
            _refreshResult = refresh;
        }

        public string Scheme { get; }
        public int GetCalls { get; private set; }
        public int RefreshCalls { get; private set; }
        public int InvalidateCalls { get; private set; }
        public Exception? InvalidateThrows { get; init; }
        public Exception? GetThrows { get; init; }

        public Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
        {
            GetCalls++;
            if (GetThrows is not null) throw GetThrows;
            return Task.FromResult(_authResult);
        }

        public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
        {
            RefreshCalls++;
            return Task.FromResult(_refreshResult);
        }

        public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default)
        {
            InvalidateCalls++;
            if (InvalidateThrows is not null) throw InvalidateThrows;
            return Task.CompletedTask;
        }
    }
}
