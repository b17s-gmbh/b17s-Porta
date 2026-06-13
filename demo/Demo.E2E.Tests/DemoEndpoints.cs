namespace Demo.E2E.Tests;

/// <summary>
/// Fixed endpoints used by the demo. These mirror the constants in the AppHost — the demo
/// pins host ports precisely so OIDC redirect URIs (and therefore these tests) are stable.
/// </summary>
internal static class DemoEndpoints
{
    public const string BffKeycloak = "http://127.0.0.1:5101";
    public const string BffZitadel = "http://127.0.0.1:5102";
    public const string Backend = "http://127.0.0.1:5100";

    public const string KeycloakDiscovery =
        "http://127.0.0.1:8080/realms/porta-demo/.well-known/openid-configuration";
    public const string ZitadelDiscovery =
        "http://127.0.0.1:8081/.well-known/openid-configuration";

    // Seeded credentials (Keycloak realm import / Zitadel first-instance config).
    public const string KeycloakUser = "demo";
    public const string KeycloakPassword = "demo";

    // Zitadel forces the org-domain suffix on the bootstrap org's login name (UserLoginMustBeDomain
    // cannot be turned off for the first instance via env), so the login name carries @zitadel.<domain>.
    public const string ZitadelUser = "demo@zitadel.127.0.0.1";
    public const string ZitadelPassword = "demo";
}
