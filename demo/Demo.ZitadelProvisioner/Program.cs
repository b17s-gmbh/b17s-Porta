using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// ===========================================================================
// Zitadel auto-provisioner (the "init step" for the demo).
//
// Keycloak ships its client in the imported realm. Zitadel has no realm import, so this
// one-shot tool creates the OIDC application the BFF needs, the moment Zitadel is up:
//
//   1. Wait for the Zitadel-generated service-account key file (seeded via
//      ZITADEL_FIRSTINSTANCE_* at first-instance init) and for Zitadel to report healthy.
//   2. Authenticate as that service account using the JWT-profile grant (RFC 7523).
//   3. Create a project + an OIDC web application with the BFF's redirect URIs.
//   4. Write the generated client id/secret to a JSON file the BFF layers over its config.
//
// The AppHost runs this as a resource and gates bff-zitadel on its completion.
// ===========================================================================

var apiBase = RequireEnv("ZITADEL_API").TrimEnd('/');
var machineKeyFile = RequireEnv("ZITADEL_MACHINE_KEY_FILE");
var outputFile = RequireEnv("DEMO_OIDC_CLIENT_FILE");
var redirectUri = RequireEnv("DEMO_REDIRECT_URI");
var postLogoutUri = RequireEnv("DEMO_POST_LOGOUT_URI");
var projectName = Environment.GetEnvironmentVariable("DEMO_PROJECT_NAME") ?? "Porta Demo";
var appName = Environment.GetEnvironmentVariable("DEMO_APP_NAME") ?? "Porta BFF (Zitadel)";

Log($"Zitadel provisioner starting. API={apiBase}");

// Idempotency: if we already wrote a usable client file (e.g. provisioner retried within the
// same Zitadel lifetime), don't create a duplicate app.
if (TryReadExistingClientId(outputFile) is { } existing)
{
    Log($"Output file already contains client '{existing}'. Nothing to do.");
    return 0;
}

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

await WaitForFileAsync(machineKeyFile, TimeSpan.FromMinutes(3));
await WaitForHealthyAsync(http, $"{apiBase}/debug/healthz", TimeSpan.FromMinutes(3));

var key = ServiceAccountKey.Load(machineKeyFile);
Log($"Loaded service-account key (userId={key.UserId}, keyId={key.KeyId}).");

var accessToken = await AuthenticateAsync(http, apiBase, key);
Log("Obtained management API access token.");

var projectId = await EnsureProjectAsync(http, apiBase, accessToken, projectName);
Log($"Project ready (id={projectId}).");

var client = await CreateOidcAppAsync(http, apiBase, accessToken, projectId, appName, redirectUri, postLogoutUri);
Log($"Created OIDC app (clientId={client.ClientId}).");

WriteClientFile(outputFile, client);
Log($"Wrote client credentials to {outputFile}.");

return 0;

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

static async Task<string> AuthenticateAsync(HttpClient http, string apiBase, ServiceAccountKey key)
{
    var assertion = key.CreateSignedJwt(audience: apiBase, lifetime: TimeSpan.FromMinutes(55));

    var form = new Dictionary<string, string>
    {
        ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ["scope"] = "openid urn:zitadel:iam:org:project:id:zitadel:aud",
        ["assertion"] = assertion,
    };

    using var resp = await http.PostAsync($"{apiBase}/oauth/v2/token", new FormUrlEncodedContent(form));
    var body = await resp.Content.ReadAsStringAsync();
    if (!resp.IsSuccessStatusCode)
    {
        throw new InvalidOperationException($"Token request failed ({(int)resp.StatusCode}): {body}");
    }

    using var doc = JsonDocument.Parse(body);
    return doc.RootElement.GetProperty("access_token").GetString()
        ?? throw new InvalidOperationException("Token response had no access_token.");
}

static async Task<string> EnsureProjectAsync(HttpClient http, string apiBase, string token, string name)
{
    // Try to create; if it already exists, search for it by name.
    using var createResp = await SendAsync(http, HttpMethod.Post, $"{apiBase}/management/v1/projects", token,
        new { name });
    var createBody = await createResp.Content.ReadAsStringAsync();
    if (createResp.IsSuccessStatusCode)
    {
        using var doc = JsonDocument.Parse(createBody);
        return doc.RootElement.GetProperty("id").GetString()!;
    }

    Log($"Project create returned {(int)createResp.StatusCode}; searching for existing project '{name}'.");

    using var searchResp = await SendAsync(http, HttpMethod.Post, $"{apiBase}/management/v1/projects/_search", token,
        new
        {
            queries = new[]
            {
                new { nameQuery = new { name, method = "TEXT_QUERY_METHOD_EQUALS" } },
            },
        });
    var searchBody = await searchResp.Content.ReadAsStringAsync();
    if (!searchResp.IsSuccessStatusCode)
    {
        throw new InvalidOperationException(
            $"Project create failed ({createBody}) and search failed ({searchBody}).");
    }

    using var searchDoc = JsonDocument.Parse(searchBody);
    if (searchDoc.RootElement.TryGetProperty("result", out var result)
        && result.ValueKind == JsonValueKind.Array
        && result.GetArrayLength() > 0)
    {
        return result[0].GetProperty("id").GetString()!;
    }

    throw new InvalidOperationException($"Could not create or find project '{name}'.");
}

static async Task<OidcClient> CreateOidcAppAsync(
    HttpClient http, string apiBase, string token, string projectId,
    string appName, string redirectUri, string postLogoutUri)
{
    var payload = new
    {
        name = appName,
        redirectUris = new[] { redirectUri },
        postLogoutRedirectUris = new[] { postLogoutUri },
        responseTypes = new[] { "OIDC_RESPONSE_TYPE_CODE" },
        grantTypes = new[] { "OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN" },
        appType = "OIDC_APP_TYPE_WEB",
        authMethodType = "OIDC_AUTH_METHOD_TYPE_BASIC",
        version = "OIDC_VERSION_1_0",
        // devMode relaxes the redirect-URI rules so http://127.0.0.1 callbacks are accepted.
        devMode = true,
        accessTokenType = "OIDC_TOKEN_TYPE_BEARER",
        idTokenRoleAssertion = true,
        idTokenUserinfoAssertion = true,
        // Zitadel v4 defaults to the Login UI v2, which runs as a SEPARATE container the demo
        // does not host — so /authorize redirects to /ui/v2/login and 404s ({"code":5,...}).
        // Pin this app to the embedded legacy login (V1) at /ui/login, which the core container
        // serves out of the box.
        loginVersion = new { loginV1 = new { } },
    };

    using var resp = await SendAsync(http, HttpMethod.Post,
        $"{apiBase}/management/v1/projects/{projectId}/apps/oidc", token, payload);
    var body = await resp.Content.ReadAsStringAsync();
    if (!resp.IsSuccessStatusCode)
    {
        throw new InvalidOperationException($"OIDC app creation failed ({(int)resp.StatusCode}): {body}");
    }

    using var doc = JsonDocument.Parse(body);
    var root = doc.RootElement;
    var clientId = root.GetProperty("clientId").GetString()
        ?? throw new InvalidOperationException("OIDC app response had no clientId.");
    var clientSecret = root.TryGetProperty("clientSecret", out var s) ? s.GetString() : null;
    return new OidcClient(clientId, clientSecret ?? string.Empty);
}

static void WriteClientFile(string path, OidcClient client)
{
    var dir = Path.GetDirectoryName(path);
    if (!string.IsNullOrEmpty(dir))
    {
        Directory.CreateDirectory(dir);
    }

    // Shape mirrors the BFF's OidcAuth config section so it merges cleanly.
    var json = JsonSerializer.Serialize(
        new { OidcAuth = new { client.ClientId, client.ClientSecret } },
        new JsonSerializerOptions { WriteIndented = true });
    File.WriteAllText(path, json);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static async Task<HttpResponseMessage> SendAsync(
    HttpClient http, HttpMethod method, string url, string bearer, object body)
{
    var req = new HttpRequestMessage(method, url);
    req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearer);
    req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
    return await http.SendAsync(req);
}

static async Task WaitForFileAsync(string path, TimeSpan timeout)
{
    Log($"Waiting for service-account key file: {path}");
    var deadline = DateTime.UtcNow + timeout;
    while (DateTime.UtcNow < deadline)
    {
        if (File.Exists(path) && new FileInfo(path).Length > 0)
        {
            return;
        }
        await Task.Delay(TimeSpan.FromSeconds(2));
    }
    throw new TimeoutException($"Service-account key file did not appear within {timeout}: {path}");
}

static async Task WaitForHealthyAsync(HttpClient http, string healthUrl, TimeSpan timeout)
{
    Log($"Waiting for Zitadel health: {healthUrl}");
    var deadline = DateTime.UtcNow + timeout;
    while (DateTime.UtcNow < deadline)
    {
        try
        {
            using var resp = await http.GetAsync(healthUrl);
            if (resp.IsSuccessStatusCode)
            {
                return;
            }
        }
        catch (HttpRequestException)
        {
            // Not up yet.
        }
        await Task.Delay(TimeSpan.FromSeconds(2));
    }
    throw new TimeoutException($"Zitadel did not become healthy within {timeout}: {healthUrl}");
}

static string? TryReadExistingClientId(string path)
{
    try
    {
        if (!File.Exists(path))
        {
            return null;
        }
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        if (doc.RootElement.TryGetProperty("OidcAuth", out var oidc)
            && oidc.TryGetProperty("ClientId", out var id))
        {
            var value = id.GetString();
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }
    }
    catch
    {
        // Corrupt/partial file: treat as not-provisioned and overwrite.
    }
    return null;
}

static string RequireEnv(string name) =>
    Environment.GetEnvironmentVariable(name)
    ?? throw new InvalidOperationException($"Required environment variable '{name}' is not set.");

static void Log(string message) =>
    Console.WriteLine($"[zitadel-provisioner] {DateTime.UtcNow:HH:mm:ss} {message}");

internal sealed record OidcClient(string ClientId, string ClientSecret);

/// <summary>
/// A Zitadel machine-user (service account) JSON key, as written by
/// <c>ZITADEL_FIRSTINSTANCE_MACHINEKEYPATH</c> with key type JSON.
/// </summary>
internal sealed record ServiceAccountKey(string UserId, string KeyId, string PrivateKeyPem)
{
    public static ServiceAccountKey Load(string path)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        return new ServiceAccountKey(
            UserId: root.GetProperty("userId").GetString()!,
            KeyId: root.GetProperty("keyId").GetString()!,
            PrivateKeyPem: root.GetProperty("key").GetString()!);
    }

    /// <summary>Builds an RS256-signed JWT-profile assertion for the token endpoint.</summary>
    public string CreateSignedJwt(string audience, TimeSpan lifetime)
    {
        var now = DateTimeOffset.UtcNow;
        var header = new Dictionary<string, object> { ["alg"] = "RS256", ["kid"] = KeyId, ["typ"] = "JWT" };
        var payload = new Dictionary<string, object>
        {
            ["iss"] = UserId,
            ["sub"] = UserId,
            ["aud"] = audience,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.Add(lifetime).ToUnixTimeSeconds(),
        };

        var signingInput =
            $"{Base64Url(JsonSerializer.SerializeToUtf8Bytes(header))}." +
            $"{Base64Url(JsonSerializer.SerializeToUtf8Bytes(payload))}";

        using var rsa = RSA.Create();
        rsa.ImportFromPem(PrivateKeyPem);
        var signature = rsa.SignData(
            Encoding.ASCII.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        return $"{signingInput}.{Base64Url(signature)}";
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
