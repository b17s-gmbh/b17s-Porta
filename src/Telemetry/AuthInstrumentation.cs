using System.Diagnostics;

using b17s.Porta.Auth.Providers;

using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Telemetry;

/// <summary>
/// Shared instrumentation for the <see cref="IAuthenticationProvider"/> resolution step. Emits the
/// <c>bff.authentication</c> span and the <c>bff.auth.*</c> metrics (<c>bff.auth.duration</c>,
/// <c>bff.auth.successes</c>, <c>bff.auth.failures</c>) around an auth-context resolution so the
/// transformer and raw-forward endpoints record identical telemetry from a single place.
/// </summary>
internal static class AuthInstrumentation
{
    /// <summary>
    /// Resolves the auth context via <paramref name="authProvider"/> while recording the
    /// authentication span/metrics. When <paramref name="allowOptional"/> is <c>true</c>, an
    /// unauthenticated result is treated as deliberate anonymous access (no success/failure counter);
    /// when <c>false</c>, an unauthenticated result is counted as a failure.
    /// </summary>
    public static async Task<AuthenticationContext> ResolveAsync(
        IAuthenticationProvider authProvider,
        HttpContext context,
        bool allowOptional,
        PortaMetrics? metrics,
        bool enableTelemetry)
    {
        using var activity = enableTelemetry
            ? PortaActivitySource.Source.StartActivity(PortaActivitySource.Activities.Authentication, ActivityKind.Internal)
            : null;
        activity?.SetTag(PortaActivitySource.Tags.Component, "authentication");

        var stopwatch = metrics != null ? Stopwatch.StartNew() : null;

        AuthenticationContext authContext;
        try
        {
            authContext = allowOptional
                ? await authProvider.TryGetAuthContextAsync(context, context.RequestAborted)
                : await authProvider.GetAuthContextAsync(context, context.RequestAborted);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            // Client disconnect mid-resolution is a normal operational event, not an auth failure:
            // leave the span green and record no success/failure counter for it.
            activity?.SetStatus(ActivityStatusCode.Ok);
            throw;
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            activity?.SetTag(PortaActivitySource.Tags.ErrorType, ex.GetType().Name);
            if (metrics != null)
            {
                metrics.RecordAuthenticationDuration(stopwatch!.Elapsed.TotalMilliseconds, "unknown");
                metrics.RecordAuthenticationFailure("provider_threw");
            }
            throw;
        }

        var provider = ShortProviderName(authContext.Scheme);

        if (metrics != null)
        {
            metrics.RecordAuthenticationDuration(stopwatch!.Elapsed.TotalMilliseconds, provider ?? "none");

            if (authContext.IsAuthenticated)
            {
                metrics.RecordAuthenticationSuccess(provider);
            }
            else if (!allowOptional)
            {
                // Required auth, but no registered provider produced a credential context.
                metrics.RecordAuthenticationFailure("unauthenticated", provider);
            }
            // optional + unauthenticated == deliberate anonymous access: neither success nor failure.
        }

        if (authContext.IsAuthenticated)
        {
            activity?.SetTag(PortaActivitySource.Tags.AuthProvider, authContext.Scheme);
            activity?.SetStatus(ActivityStatusCode.Ok);
        }
        else if (!allowOptional)
        {
            activity?.SetStatus(ActivityStatusCode.Error, "unauthenticated");
        }

        return authContext;
    }

    /// <summary>
    /// Shortens a provider <see cref="IAuthenticationProvider.Scheme"/> (which defaults to the
    /// full type name) to its trailing segment for a low-cardinality, readable <c>provider</c> tag
    /// (e.g. <c>b17s.Porta.Auth.Providers.SessionAuthProvider</c> → <c>SessionAuthProvider</c>).
    /// Custom schemes without a dot are used verbatim.
    /// </summary>
    private static string? ShortProviderName(string? scheme)
    {
        if (string.IsNullOrEmpty(scheme))
        {
            return null;
        }

        var lastDot = scheme.LastIndexOf('.');
        return lastDot >= 0 && lastDot < scheme.Length - 1 ? scheme[(lastDot + 1)..] : scheme;
    }
}
