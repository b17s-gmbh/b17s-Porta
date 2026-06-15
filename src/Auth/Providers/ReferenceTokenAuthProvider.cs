using b17s.Porta.Auth.Tokens;

using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Auth.Providers;

/// <summary>
/// Reference token (opaque token) authentication provider. Resolves the backend
/// <see cref="AuthenticationContext"/> (access token + claims) for outbound calls by delegating the
/// introspection/binding/cache work to the shared <see cref="ReferenceTokenAuthenticator"/>.
/// </summary>
/// <remarks>
/// This populates the transformer's <c>AuthContext</c>; it does <b>not</b> set
/// <see cref="HttpContext.User"/>. To gate endpoints with <c>RequireAuth()</c> on an opaque token,
/// register the <c>PortaReferenceToken</c> authentication scheme (which shares the same
/// <see cref="ReferenceTokenAuthenticator"/>, so the token is introspected once per request).
/// </remarks>
public sealed class ReferenceTokenAuthProvider(ReferenceTokenAuthenticator authenticator) : IAuthenticationProvider
{
    /// <inheritdoc/>
    public async Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        var authContext = new AuthenticationContext();

        if (!authenticator.TryExtractToken(context.Request, out var token))
        {
            return authContext;
        }

        authContext.AccessToken = token;

        var result = await authenticator.AuthenticateAsync(context, token, cancellationToken);
        if (result is null)
        {
            // Inactive / failed binding / introspection unavailable - fail closed.
            authContext.AccessToken = null;
            return authContext;
        }

        authContext.ExpiresAt = result.ExpiresAt;
        foreach (var claim in result.Claims)
        {
            // Introspection results are already flattened to a single value per claim type
            // (multi-valued aud is JSON-encoded into one string upstream), so wrap as a
            // one-element array to match the multi-valued AuthenticationContext.Claims shape.
            authContext.Claims[claim.Key] = [claim.Value];
        }

        return authContext;
    }

    /// <summary>
    /// Reference tokens don't support refresh - they are validated via introspection each time.
    /// </summary>
    public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
        => Task.FromResult<AuthenticationContext?>(null);

    /// <inheritdoc/>
    public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default)
        => authenticator.InvalidateAsync(context, cancellationToken);

    /// <summary>
    /// Builds the introspection cache key. Retained as a thin forwarder to
    /// <see cref="ReferenceTokenAuthenticator.BuildIntrospectionCacheKey"/> for callers/tests that
    /// reference it by this name.
    /// </summary>
    internal static string BuildIntrospectionCacheKey(string token)
        => ReferenceTokenAuthenticator.BuildIntrospectionCacheKey(token);
}
