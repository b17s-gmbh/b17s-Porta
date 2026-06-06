using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace b17s.Porta.Auth.Providers;

/// <summary>
/// Composes multiple <see cref="IAuthenticationProvider"/> implementations into a single
/// provider so a BFF can accept several credential types (session cookie, JWT bearer,
/// reference token, custom API key, etc.) on the same endpoints.
/// </summary>
/// <remarks>
/// Resolution model:
/// <list type="bullet">
///   <item><b>GetAuthContextAsync</b>: providers are tried in registration order; the first
///     to return an authenticated context wins. The winner's <see cref="IAuthenticationProvider.Scheme"/>
///     is stamped onto the returned <see cref="AuthenticationContext.Scheme"/> for refresh routing.</item>
///   <item><b>RefreshAsync</b>: routed to the provider whose <see cref="IAuthenticationProvider.Scheme"/>
///     matches the current context's <see cref="AuthenticationContext.Scheme"/>. Returns <c>null</c>
///     if no matching provider is registered (e.g., the provider was removed at runtime).</item>
///   <item><b>InvalidateAsync</b>: fans out to every registered provider. Logout should clear every
///     credential surface - session sign-out, reference-token cache eviction, etc. - and the
///     built-ins are individually idempotent.</item>
/// </list>
/// </remarks>
internal sealed class CompositeAuthenticationProvider(
    IReadOnlyList<IAuthenticationProvider> providers,
    ILogger<CompositeAuthenticationProvider> logger) : IAuthenticationProvider
{
    public string Scheme => "Composite";

    public async Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        for (var i = 0; i < providers.Count; i++)
        {
            var provider = providers[i];
            var result = await provider.GetAuthContextAsync(context, cancellationToken);
            if (result.IsAuthenticated)
            {
                result.Scheme = provider.Scheme;

                if (logger.IsEnabled(LogLevel.Debug) && HasMixedCredentials(context))
                {
                    logger.MultipleCredentialsPresent(provider.Scheme);
                }

                return result;
            }
        }

        return AuthenticationContext.Unauthenticated();
    }

    public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(current.Scheme))
        {
            return Task.FromResult<AuthenticationContext?>(null);
        }

        for (var i = 0; i < providers.Count; i++)
        {
            if (string.Equals(providers[i].Scheme, current.Scheme, StringComparison.Ordinal))
            {
                return providers[i].RefreshAsync(current, cancellationToken);
            }
        }

        logger.RefreshSchemeUnknown(current.Scheme);
        return Task.FromResult<AuthenticationContext?>(null);
    }

    public async Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        for (var i = 0; i < providers.Count; i++)
        {
            var provider = providers[i];
            try
            {
                await provider.InvalidateAsync(context, cancellationToken);
                logger.InvalidatedScheme(provider.Scheme);
            }
            catch (Exception ex)
            {
                // One provider's invalidate failure should not block sibling providers from
                // also clearing their credential surface. Logout is best-effort across all.
                logger.InvalidateFailed(provider.Scheme, ex);
            }
        }
    }

    /// <summary>
    /// Returns true when the inbound request carries credential indicators for more than one
    /// of the built-in providers - specifically, both an Authorization header (used by JWT
    /// and reference-token providers) and a cookie auth ticket (used by SessionAuthProvider).
    /// Used only to decide whether to emit a Debug-level diagnostic; never affects routing.
    /// </summary>
    private static bool HasMixedCredentials(HttpContext context)
    {
        var hasAuthHeader = context.Request.Headers.ContainsKey("Authorization");
        if (!hasAuthHeader)
        {
            return false;
        }

        // Cheap heuristic: a request that also carries the cookie-auth scheme's cookie has
        // two credential surfaces. We don't enumerate every cookie - just check whether any
        // cookie name begins with the .AspNetCore. prefix that the cookie auth handler emits.
        foreach (var cookie in context.Request.Cookies)
        {
            if (cookie.Key.StartsWith(".AspNetCore.", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

internal static partial class CompositeAuthenticationProviderLogging
{
    [LoggerMessage(EventId = 13610, Level = LogLevel.Debug,
        Message = "Request authenticated by scheme '{Scheme}'; additional credentials were also present (header + cookie). Registration order determined which provider matched.")]
    public static partial void MultipleCredentialsPresent(this ILogger logger, string scheme);

    [LoggerMessage(EventId = 13611, Level = LogLevel.Information,
        Message = "Invalidated authentication for scheme '{Scheme}'")]
    public static partial void InvalidatedScheme(this ILogger logger, string scheme);

    [LoggerMessage(EventId = 13612, Level = LogLevel.Warning,
        Message = "Failed to invalidate scheme '{Scheme}'; continuing with remaining providers")]
    public static partial void InvalidateFailed(this ILogger logger, string scheme, Exception ex);

    [LoggerMessage(EventId = 13613, Level = LogLevel.Warning,
        Message = "Refresh requested for scheme '{Scheme}' but no provider with that scheme is registered")]
    public static partial void RefreshSchemeUnknown(this ILogger logger, string scheme);
}
