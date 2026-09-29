namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Key material for the <c>private_key_jwt</c> client authentication method (RFC 7523 §2.2,
/// OIDC Core §9): instead of a shared secret, the client sends a short-lived JWT signed with
/// its private key as <c>client_assertion</c>. Set exactly one of <see cref="KeyFile"/> or
/// <see cref="Key"/> to enable it.
/// <para>
/// Supported key material (detected from the content):
/// <list type="bullet">
/// <item>Zitadel application key file (JSON with <c>type</c> = <c>application</c>, <c>keyId</c>, <c>key</c>, <c>clientId</c>).
/// Supplies the client id and <c>kid</c> itself.</item>
/// <item>PEM private key (RSA or EC; PKCS#1, SEC1 or PKCS#8, optionally encrypted), e.g. from Okta or Keycloak.
/// If the PEM also contains the matching <c>CERTIFICATE</c>, its thumbprints are sent as <c>x5t</c> /
/// <c>x5t#S256</c> (required by Microsoft Entra ID).</item>
/// <item>PKCS#12 / PFX file (<see cref="KeyFile"/> only), e.g. a Keycloak-generated keystore or an Entra
/// certificate credential. Thumbprints are sent as for PEM certificates.</item>
/// </list>
/// </para>
/// </summary>
public sealed class PrivateKeyJwtOptions
{
    /// <summary>
    /// Path to the key material: a Zitadel key file, a PEM file, or a PKCS#12 (<c>.pfx</c>/<c>.p12</c>) file.
    /// Read once per configured value; overwriting the file in place requires a restart.
    /// </summary>
    public string? KeyFile { get; set; }

    /// <summary>
    /// Inline key material (Zitadel key file JSON or PEM), as an alternative to <see cref="KeyFile"/>
    /// when the key comes from a secret store or environment variable. Secret-classified - never log this value.
    /// </summary>
    public string? Key { get; set; }

    /// <summary>
    /// Password for a PKCS#12 file or an encrypted PEM key (<c>ENCRYPTED PRIVATE KEY</c>).
    /// Secret-classified - never log this value.
    /// </summary>
    public string? KeyPassword { get; set; }

    /// <summary>
    /// The <c>kid</c> header of the assertion, identifying the key registered at the IdP (e.g. the key ID
    /// shown in the Okta console). Defaults to the Zitadel key file's <c>keyId</c>; otherwise omitted.
    /// </summary>
    public string? KeyId { get; set; }

    /// <summary>
    /// JWS signing algorithm. Defaults to <c>RS256</c> for RSA keys and <c>ES256</c>/<c>ES384</c>/<c>ES512</c>
    /// for EC keys by curve. RSA keys also accept <c>RS384</c>, <c>RS512</c>, <c>PS256</c>, <c>PS384</c>, <c>PS512</c>.
    /// </summary>
    public string? Algorithm { get; set; }

    /// <summary>
    /// The assertion's <c>aud</c> claim. Defaults depend on the flow: the issuer from discovery for
    /// reference-token introspection (Zitadel, Keycloak), the token endpoint for client credentials
    /// (Entra ID, Okta, Keycloak). Okta requires the URL of the endpoint being called, so set this to the
    /// introspection endpoint URL when introspecting against Okta.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>True when <see cref="KeyFile"/> or <see cref="Key"/> is set.</summary>
    internal bool IsConfigured => !string.IsNullOrEmpty(KeyFile) || !string.IsNullOrEmpty(Key);
}
