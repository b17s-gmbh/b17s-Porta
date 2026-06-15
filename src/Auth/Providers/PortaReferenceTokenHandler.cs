using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;

using b17s.Porta.Auth.Tokens;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Auth.Providers;

/// <summary>
/// Well-known names for the reference-token authentication scheme.
/// </summary>
public static class PortaReferenceTokenDefaults
{
    /// <summary>The scheme name registered by <c>AddPortaReferenceTokenScheme</c>.</summary>
    public const string AuthenticationScheme = "PortaReferenceToken";
}

/// <summary>
/// A first-class ASP.NET Core authentication scheme for opaque (reference) tokens. Introspects the
/// inbound token via the shared <see cref="ReferenceTokenAuthenticator"/> and, on success, returns an
/// <see cref="AuthenticationTicket"/> whose principal carries the introspection claims.
/// <para/>
/// Because this populates <see cref="Microsoft.AspNetCore.Http.HttpContext.User"/> through the
/// standard authentication middleware, <c>RequireAuth()</c> and the per-endpoint principal gate work
/// for opaque tokens with no consumer-side auth code - the same way they already do for cookie/OIDC
/// and JWT bearer. It composes with those schemes via standard multi-scheme selection.
/// </summary>
internal sealed class PortaReferenceTokenHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    ReferenceTokenAuthenticator authenticator)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // No credential for this scheme: return NoResult (not Fail) so multi-scheme setups can try
        // another handler and anonymous endpoints aren't disturbed.
        if (!authenticator.TryExtractToken(Request, out var token))
        {
            return AuthenticateResult.NoResult();
        }

        var result = await authenticator.AuthenticateAsync(Context, token, Context.RequestAborted);
        if (result is null)
        {
            return AuthenticateResult.Fail("Reference token is inactive, failed binding validation, or could not be introspected.");
        }

        // The introspection layer flattens claims into a Dictionary<string,string>, collapsing
        // multi-valued claims into a single string (a JSON array for roles/aud, a space-delimited
        // list for scope). Expand them back into one Claim per value here - the first place these
        // become a ClaimsPrincipal - so role- and scope-based authorization actually works.
        var identity = new ClaimsIdentity(
            ExpandClaims(result.Claims),
            authenticationType: PortaReferenceTokenDefaults.AuthenticationScheme,
            nameType: "sub",
            roleType: "role");

        var ticket = new AuthenticationTicket(
            new ClaimsPrincipal(identity),
            PortaReferenceTokenDefaults.AuthenticationScheme);

        return AuthenticateResult.Success(ticket);
    }

    /// <summary>
    /// Projects the flat introspection claim dictionary into <see cref="Claim"/>s, un-flattening the
    /// two multi-valued encodings the introspection layer collapses into a single string so that
    /// role- and scope-based authorization match:
    /// <list type="bullet">
    /// <item>A JSON-array value (e.g. a <c>role</c> claim the IdP returned as <c>["admin","user"]</c>,
    /// which the mapper stores verbatim as <c>JsonElement.ToString()</c>) becomes one claim per
    /// element - so <c>User.IsInRole("admin")</c> and <c>[Authorize(Roles="admin")]</c> match.</item>
    /// <item>The space-delimited OAuth <c>scope</c> claim becomes one <c>scope</c> claim per value,
    /// the shape RFC 7662 introspection consumers conventionally expand it to.</item>
    /// </list>
    /// Each claim is issued under the token's own <c>iss</c> (when present) rather than the default
    /// "LOCAL AUTHORITY", so policies that match on <see cref="Claim.Issuer"/> see the real issuer.
    /// </summary>
    private static IEnumerable<Claim> ExpandClaims(IReadOnlyDictionary<string, string> claims)
    {
        // Null issuer => Claim falls back to ClaimsIdentity.DefaultIssuer ("LOCAL AUTHORITY").
        var issuer = claims.GetValueOrDefault("iss") is { Length: > 0 } iss ? iss : null;

        foreach (var (key, value) in claims)
        {
            if (TryGetJsonArrayValues(value, out var arrayValues))
            {
                foreach (var element in arrayValues)
                {
                    yield return new Claim(key, element, ClaimValueTypes.String, issuer);
                }
            }
            else if (key == "scope")
            {
                foreach (var scope in value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    yield return new Claim(key, scope, ClaimValueTypes.String, issuer);
                }
            }
            else
            {
                yield return new Claim(key, value, ClaimValueTypes.String, issuer);
            }
        }
    }

    /// <summary>
    /// Recognises the JSON-array encoding the introspection mapper uses for multi-valued claims
    /// (<c>JsonElement.ToString()</c> renders an array as <c>["a","b"]</c>) and returns the string
    /// projection of each primitive element. Non-array or unparseable values return
    /// <see langword="false"/> so the caller treats them as a single scalar claim.
    /// </summary>
    private static bool TryGetJsonArrayValues(string value, out List<string> values)
    {
        values = [];

        // Fast reject: only a '[' can begin a JSON array, so the common scalar case skips the parser.
        if (value.Length == 0 || value[0] != '[')
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(value);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (var element in doc.RootElement.EnumerateArray())
            {
                // Roles/scopes/audiences are always primitives; a flat string identity can't carry a
                // nested array/object, and null elements are dropped.
                var projected = element.ValueKind switch
                {
                    JsonValueKind.String => element.GetString(),
                    JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => element.GetRawText(),
                    _ => null
                };
                if (projected is not null)
                {
                    values.Add(projected);
                }
            }

            return values.Count > 0;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
