namespace b17s.Porta.Configuration;

/// <summary>
/// Configuration for OIDC authentication in the BFF.
/// Wraps the session authentication settings with a cleaner API for library users.
/// </summary>
/// <remarks>
/// This class provides a clean configuration API for users who opt-in to OIDC authentication.
/// It inherits from <see cref="SessionAuthenticationConfiguration"/> for backward compatibility.
///
/// Usage in appsettings.json:
/// <code>
/// "OidcAuth": {
///   "Authority": "https://auth.example.com",
///   "ClientId": "my-porta",
///   "ClientSecret": "secret",
///   "Scope": "openid profile email"
/// }
/// </code>
///
/// Registration:
/// <code>
/// builder.Services.Configure&lt;OidcAuthOptions&gt;(
///     builder.Configuration.GetSection(OidcAuthOptions.SectionName));
/// </code>
/// </remarks>
public sealed class OidcAuthOptions : SessionAuthenticationConfiguration
{
    /// <summary>
    /// Configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "OidcAuth";
}
