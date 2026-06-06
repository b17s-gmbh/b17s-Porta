using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

var app = builder.Build();

app.MapDefaultEndpoints();

// ---------------------------------------------------------------------------
// Demo downstream API.
//
// The BFF (b17s.Porta) sits in front of this service and forwards requests to it.
// This stands in for "your real internal microservice". It is intentionally tiny:
//   GET /weather   - public sample data the BFF aggregates / passes through.
//   GET /me        - echoes the forwarded user identity so the demo can prove the
//                    BFF forwarded the user's access token (BackendAuthPolicies.BearerToken).
//   GET /internal  - protected by HTTP Basic auth; rejects callers without valid service
//                    credentials, proving the BFF authenticated with its OWN credentials
//                    (BackendAuthPolicies.BasicAuth) rather than the end user's token.
// ---------------------------------------------------------------------------

// Service credentials the BFF must present to reach /internal. In a real system these would be
// a secret store entry, not config; the demo keeps them in config so the AppHost can hand the
// same pair to both the backend (expected) and the BFF (presented).
var expectedBasicUser = builder.Configuration["Demo:BasicAuthUsername"] ?? "bff-service";
var expectedBasicPassword = builder.Configuration["Demo:BasicAuthPassword"] ?? "porta-basic-demo-secret";

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching",
};

app.MapGet("/weather", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index => new WeatherForecast(
        DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
        Random.Shared.Next(-20, 55),
        summaries[Random.Shared.Next(summaries.Length)]))
        .ToArray();
    return forecast;
});

app.MapGet("/me", (HttpContext ctx) =>
{
    // The BFF forwards the user's bearer token when an endpoint uses
    // BackendAuthPolicies.BearerToken. We surface whatever arrived so the demo can
    // visibly prove the token made it through the BFF.
    //
    // NOTE: This decodes the JWT payload WITHOUT validating its signature. That is fine
    // for a read-only demo echo, but a real backend MUST validate the token (issuer,
    // audience, signature, lifetime) before trusting any claim.
    var authHeader = ctx.Request.Headers.Authorization.ToString();
    var hasToken = authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);

    string? subject = null;
    string? preferredUsername = null;
    string? issuer = null;
    if (hasToken)
    {
        var rawToken = authHeader["Bearer ".Length..].Trim();
        var claims = TryReadJwtClaims(rawToken);
        if (claims is not null)
        {
            subject = GetString(claims, "sub");
            issuer = GetString(claims, "iss");
            preferredUsername = GetString(claims, "preferred_username") ?? GetString(claims, "email");
        }
    }

    return Results.Ok(new BackendIdentity(
        ServedBy: "Demo.Api",
        UserTokenForwarded: hasToken,
        Subject: subject,
        PreferredUsername: preferredUsername,
        Issuer: issuer));
});

app.MapGet("/internal", (HttpContext ctx) =>
{
    // Authenticate the *caller* (the BFF) by a shared service credential over HTTP Basic.
    // This stands in for an internal service that trusts callers by a machine credential
    // rather than an end-user token. Reject anything without valid credentials so the demo
    // proves the BFF supplied them (BackendAuthPolicies.BasicAuth).
    if (!TryValidateBasicAuth(ctx.Request, expectedBasicUser, expectedBasicPassword, out var caller))
    {
        ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"Demo.Api\"";
        return Results.Unauthorized();
    }

    return Results.Ok(new InternalResource(
        ServedBy: "Demo.Api",
        BasicAuthValidated: true,
        AuthenticatedAs: caller,
        Message: "Reached the Basic-auth-protected backend endpoint - the BFF authenticated with its service credentials."));
});

app.Run();

static bool TryValidateBasicAuth(HttpRequest request, string expectedUser, string expectedPassword, out string caller)
{
    caller = string.Empty;

    var header = request.Headers.Authorization.ToString();
    if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
    {
        return false;
    }

    string decoded;
    try
    {
        decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header["Basic ".Length..].Trim()));
    }
    catch (FormatException)
    {
        return false;
    }

    var separator = decoded.IndexOf(':');
    if (separator < 0)
    {
        return false;
    }

    var user = decoded[..separator];
    var password = decoded[(separator + 1)..];
    if (!string.Equals(user, expectedUser, StringComparison.Ordinal)
        || !string.Equals(password, expectedPassword, StringComparison.Ordinal))
    {
        return false;
    }

    caller = user;
    return true;
}

static JsonElement? TryReadJwtClaims(string token)
{
    var parts = token.Split('.');
    if (parts.Length < 2)
    {
        return null;
    }

    try
    {
        var payload = Base64UrlDecode(parts[1]);
        using var doc = JsonDocument.Parse(payload);
        // Clone so the JsonElement survives disposal of the document.
        return doc.RootElement.Clone();
    }
    catch
    {
        return null;
    }
}

static byte[] Base64UrlDecode(string input)
{
    var s = input.Replace('-', '+').Replace('_', '/');
    switch (s.Length % 4)
    {
        case 2: s += "=="; break;
        case 3: s += "="; break;
    }
    return Convert.FromBase64String(s);
}

static string? GetString(JsonElement? element, string property) =>
    element is { } e && e.ValueKind == JsonValueKind.Object && e.TryGetProperty(property, out var value)
        ? value.GetString()
        : null;

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

internal record BackendIdentity(
    string ServedBy,
    bool UserTokenForwarded,
    string? Subject,
    string? PreferredUsername,
    string? Issuer);

internal record InternalResource(
    string ServedBy,
    bool BasicAuthValidated,
    string AuthenticatedAs,
    string Message);
