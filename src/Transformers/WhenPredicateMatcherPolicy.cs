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
    /// Applies the predicate evaluation to filter the candidate set.
    /// Endpoints with predicates that return false are marked invalid.
    /// Endpoints without predicates remain valid (default behavior).
    /// </summary>
    public Task ApplyAsync(HttpContext httpContext, CandidateSet candidates)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(candidates);

        for (var i = 0; i < candidates.Count; i++)
        {
            if (!candidates.IsValidCandidate(i))
            {
                continue;
            }

            var endpoint = candidates[i].Endpoint;
            var predicateMetadata = endpoint.Metadata.GetMetadata<WhenPredicateMetadata>();

            if (predicateMetadata is not null)
            {
                // Evaluate the predicate - if false, this endpoint won't handle the request
                var isValid = predicateMetadata.Predicate(httpContext);
                candidates.SetValidity(i, isValid);
            }
            // Endpoints without predicate metadata remain valid
        }

        return Task.CompletedTask;
    }
}
