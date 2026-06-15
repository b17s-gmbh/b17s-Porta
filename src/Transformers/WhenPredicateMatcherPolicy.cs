using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Matching;

namespace b17s.Porta.Transformers;

/// <summary>
/// Metadata that stores a predicate for conditional endpoint matching.
/// </summary>
/// <remarks>
/// Creates new predicate metadata.
/// </remarks>
/// <param name="predicate">The predicate to evaluate at request time</param>
public sealed class WhenPredicateMetadata(Func<HttpContext, bool> predicate)
{
    /// <summary>
    /// The predicate function that determines if this endpoint should handle the request.
    /// </summary>
    public Func<HttpContext, bool> Predicate { get; } = predicate ?? throw new ArgumentNullException(nameof(predicate));
}

/// <summary>
/// A MatcherPolicy that evaluates When() predicates during endpoint selection.
/// Endpoints with predicates that return false are marked as invalid, allowing
/// other matching endpoints to be selected instead.
/// </summary>
/// <remarks>
/// This runs during the endpoint selection phase, before authorization middleware executes.
/// The matching pipeline is: Route Matching -> Matcher Policies -> Endpoint Selection -> Authorization -> Handler
/// <para/>
/// This enables conditional routing scenarios like:
/// - Feature flags: route to different handlers based on feature state
/// - A/B testing: conditionally route based on user segments
/// - Header-based routing: handle only requests with specific headers
/// - Query parameter routing: match based on query string values
/// </remarks>
public sealed class WhenPredicateMatcherPolicy : MatcherPolicy, IEndpointSelectorPolicy
{
    /// <summary>
    /// Order determines when this policy runs relative to other matcher policies.
    /// Lower values run first. We use int.MaxValue - 100 to run after most built-in policies
    /// (like HTTP method matching) but still during endpoint selection, before authorization.
    /// </summary>
    public override int Order => int.MaxValue - 100;

    /// <summary>
    /// Determines if this policy applies to any of the given endpoints.
    /// </summary>
    public bool AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        for (var i = 0; i < endpoints.Count; i++)
        {
            if (endpoints[i].Metadata.GetMetadata<WhenPredicateMetadata>() is not null)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Applies the predicate evaluation to filter the candidate set, implementing
    /// "a guarded endpoint wins its route when its predicate is true; an unguarded endpoint on the
    /// same route is the fallback".
    /// <para/>
    /// Endpoints whose predicate returns <c>false</c> are marked invalid. When a guarded endpoint's
    /// predicate returns <c>true</c>, any <em>unguarded</em> endpoint that shares the same route
    /// precedence is marked invalid so the guarded endpoint is selected instead of colliding with it
    /// (which would raise <see cref="Microsoft.AspNetCore.Routing.Matching.AmbiguousMatchException"/>).
    /// When no guard matches, unguarded endpoints are left untouched and normal precedence selects the
    /// fallback. Two guarded endpoints on the same route whose predicates are both true remain a
    /// genuine ambiguity — give overlapping variants mutually-exclusive predicates.
    /// </summary>
    public Task ApplyAsync(HttpContext httpContext, CandidateSet candidates)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(candidates);

        // Pass 1: evaluate each guarded candidate. A false predicate drops it from selection; a true
        // one stays valid. Unguarded candidates are left as-is for now.
        var anyGuardSatisfied = false;
        for (var i = 0; i < candidates.Count; i++)
        {
            if (!candidates.IsValidCandidate(i))
            {
                continue;
            }

            var predicateMetadata = candidates[i].Endpoint.Metadata.GetMetadata<WhenPredicateMetadata>();
            if (predicateMetadata is null)
            {
                continue;
            }

            var matched = predicateMetadata.Predicate(httpContext);
            candidates.SetValidity(i, matched);
            anyGuardSatisfied |= matched;
        }

        if (!anyGuardSatisfied)
        {
            // No guard matched: any unguarded endpoint on the route is the fallback. Leave the
            // candidate set untouched so normal precedence selects it.
            return Task.CompletedTask;
        }

        // Pass 2: collect the route-precedence buckets (Score) that still hold a satisfied guard. An
        // unguarded endpoint sharing a bucket with a satisfied guard would tie with it and trigger
        // AmbiguousMatchException, so the guard must win the bucket.
        var guardedScores = new HashSet<int>();
        for (var i = 0; i < candidates.Count; i++)
        {
            if (candidates.IsValidCandidate(i)
                && candidates[i].Endpoint.Metadata.GetMetadata<WhenPredicateMetadata>() is not null)
            {
                guardedScores.Add(candidates[i].Score);
            }
        }

        // Pass 3: drop unguarded candidates that collide with a satisfied guard at the same
        // precedence. Unguarded endpoints at other precedences are left for normal routing.
        for (var i = 0; i < candidates.Count; i++)
        {
            if (candidates.IsValidCandidate(i)
                && candidates[i].Endpoint.Metadata.GetMetadata<WhenPredicateMetadata>() is null
                && guardedScores.Contains(candidates[i].Score))
            {
                candidates.SetValidity(i, false);
            }
        }

        return Task.CompletedTask;
    }
}
