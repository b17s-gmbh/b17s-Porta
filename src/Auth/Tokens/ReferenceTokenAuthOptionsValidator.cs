using Microsoft.Extensions.Options;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Validates <see cref="ReferenceTokenAuthOptions"/> at startup so a misconfigured BFF
/// fails on boot - mirroring the OIDC fail-at-boot posture of
/// <see cref="b17s.Porta.Configuration.SessionAuthenticationConfigurationValidator"/> -
/// instead of rejecting every request at introspection time (empty Authority, exhausted
/// audience allow-lists) or throwing from the distributed cache (non-positive durations).
///
/// Wired in <see cref="b17s.Porta.Extensions.AuthenticationServiceExtensions"/> via
/// <c>AddReferenceTokenAuthentication</c> together with <c>ValidateOnStart()</c>. The
/// runtime reads these options through <c>IOptionsMonitor.CurrentValue</c> for hot
/// reload; startup validation covers the initial snapshot only, so a bad appsettings
/// reload still surfaces at request time.
/// </summary>
internal sealed class ReferenceTokenAuthOptionsValidator : IValidateOptions<ReferenceTokenAuthOptions>
{
    public ValidateOptionsResult Validate(string? name, ReferenceTokenAuthOptions options)
    {
        var errors = new List<string>();

        // Authority is treated opaquely (it doubles as the default expected issuer,
        // compared byte-for-byte against the iss claim) - validate only that it is
        // present and parseable as an absolute http(s) URL, same as the session-auth
        // validator.
        if (string.IsNullOrWhiteSpace(options.Authority))
        {
            errors.Add("ReferenceTokenAuth.Authority is required.");
        }
        else if (!Uri.TryCreate(options.Authority, UriKind.Absolute, out var authorityUri)
            || (authorityUri.Scheme != Uri.UriSchemeHttp && authorityUri.Scheme != Uri.UriSchemeHttps))
        {
            errors.Add(
                $"ReferenceTokenAuth.Authority must be an absolute http(s) URL. " +
                $"Got: '{options.Authority}'.");
        }

        // An empty header name never matches a request header, so no token would
        // ever be accepted - silently.
        if (string.IsNullOrWhiteSpace(options.TokenHeaderName))
        {
            errors.Add("ReferenceTokenAuth.TokenHeaderName is required.");
        }

        // Introspection client credentials are optional (an open introspection endpoint
        // needs neither), but ReferenceTokenService only attaches them when BOTH are
        // set - configuring exactly one is silently ignored.
        if (string.IsNullOrEmpty(options.ClientId) != string.IsNullOrEmpty(options.ClientSecret))
        {
            errors.Add(
                "ReferenceTokenAuth.ClientId and ClientSecret must be configured together. " +
                "Introspection credentials are only sent when both are set; a lone value is " +
                "silently ignored.");
        }

        // Used as the distributed-cache entry lifetime when the introspection response
        // carries no exp claim; the cache rejects non-positive lifetimes at request time.
        if (options.DefaultCacheDuration <= TimeSpan.Zero)
        {
            errors.Add(
                $"ReferenceTokenAuth.DefaultCacheDuration must be > 0. " +
                $"Got: {options.DefaultCacheDuration}.");
        }

        if (options.MaxCacheDuration < options.DefaultCacheDuration)
        {
            errors.Add(
                $"ReferenceTokenAuth.MaxCacheDuration must be >= DefaultCacheDuration " +
                $"({options.DefaultCacheDuration}). Got: {options.MaxCacheDuration}.");
        }

        // With audience validation on but no allow-list configured, ValidateBinding
        // rejects every token - the BFF would boot fine and then 401 everything.
        if (options.ValidateAudience
            && options.ValidAudiences.Count == 0
            && options.ValidClientIds.Count == 0)
        {
            errors.Add(
                "ReferenceTokenAuth.ValidateAudience is true but neither ValidAudiences nor " +
                "ValidClientIds is configured - every token would be rejected. Configure at " +
                "least one allow-list, or set ValidateAudience=false (only safe when the " +
                "introspection endpoint is dedicated to a single relying party).");
        }

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }
}
