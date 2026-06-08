namespace b17s.Porta.Auth;

/// <summary>
/// Helpers for telling cooperative cancellation apart from genuine faults inside the
/// auth / token / discovery exception handlers.
/// </summary>
internal static class CancellationExtensions
{
    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="exception"/> represents cooperative
    /// cancellation triggered by <paramref name="cancellationToken"/> - i.e. an
    /// <see cref="OperationCanceledException"/> raised after the caller's token actually fired.
    /// </summary>
    /// <remarks>
    /// Designed for use as an exception-filter predicate: <c>catch (Exception ex) when
    /// (!ex.IsCanceledBy(token))</c>. When the predicate returns <see langword="false"/> the
    /// <c>catch</c> block is never entered, so the original cancellation keeps propagating from its
    /// throw site with the stack intact - it is not laundered into a transient auth/token failure
    /// (request abort, request timeout, and host shutdown then actually stop the work). An
    /// HttpClient timeout surfaces as a <see cref="TaskCanceledException"/> whose token did NOT
    /// fire, so it returns <see langword="false"/> here and stays on the normal failure path.
    /// </remarks>
    /// <param name="exception">The exception observed in the catch handler.</param>
    /// <param name="cancellationToken">The token the surrounding operation was invoked with.</param>
    /// <returns>
    /// <see langword="true"/> if the exception is cancellation caused by <paramref name="cancellationToken"/>;
    /// otherwise <see langword="false"/>.
    /// </returns>
    public static bool IsCanceledBy(this Exception exception, CancellationToken cancellationToken)
        => exception is OperationCanceledException && cancellationToken.IsCancellationRequested;
}
