using System.Security.Claims;

using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Demo.Bff.Pages;

/// <summary>
/// Backing model for the demo landing page. Surfaces the current session state and the
/// seeded demo credentials so the demo is clickable in a browser without a SPA.
/// </summary>
public sealed class IndexModel(IConfiguration configuration) : PageModel
{
    /// <summary>The identity provider label for this instance (e.g. <c>Keycloak</c>, <c>Zitadel</c>).</summary>
    public string Provider { get; private set; } = "OIDC";

    /// <summary>Whether the current BFF session is authenticated.</summary>
    public bool IsAuthenticated { get; private set; }

    /// <summary>Best-effort display name for the signed-in user; null when anonymous.</summary>
    public string? UserName { get; private set; }

    /// <summary>The seeded demo login for this provider, shown only when signed out; null when unknown.</summary>
    public (string User, string Password)? DemoLogin { get; private set; }

    /// <summary>The Porta flows a visitor can invoke inline from the landing page.</summary>
    public IReadOnlyList<ApiEndpoint> Endpoints { get; } =
    [
        new("GET", "/bff/user", "BFF session identity, read from the auth cookie.", RequiresAuth: true),
        new("GET", "/api/weather", "Zero-code pass-through to the public backend endpoint.", RequiresAuth: false),
        new("GET", "/api/internal", "Pass-through where the BFF authenticates to the backend with HTTP Basic service credentials.", RequiresAuth: true),
        new("GET", "/api/me", "Pass-through that forwards your access token to the backend.", RequiresAuth: true),
        new("GET", "/api/dashboard", "Aggregating transformer with mixed per-backend auth: /me (Bearer) + /weather (None) + /internal (Basic) in parallel.", RequiresAuth: true),
    ];

    /// <summary>Resolves the session state for the GET render.</summary>
    public void OnGet()
    {
        Provider = configuration["Demo:ProviderLabel"] ?? "OIDC";
        IsAuthenticated = User.Identity?.IsAuthenticated == true;

        if (IsAuthenticated)
        {
            UserName = User.Identity?.Name
                ?? User.FindFirst("preferred_username")?.Value
                ?? User.FindFirst(ClaimTypes.Email)?.Value
                ?? User.FindFirst("sub")?.Value
                ?? "(unknown)";
        }
        else
        {
            DemoLogin = Provider switch
            {
                "Keycloak" => ("demo", "demo"),
                // Zitadel forces the org-domain suffix on the bootstrap org's login name.
                "Zitadel" => ("demo@zitadel.127.0.0.1", "demo"),
                _ => null,
            };
        }
    }

    /// <summary>A BFF endpoint a visitor can invoke inline from the landing page.</summary>
    /// <param name="Method">HTTP method.</param>
    /// <param name="Path">Same-origin path on the BFF.</param>
    /// <param name="Description">One-line explanation of the Porta flow it exercises.</param>
    /// <param name="RequiresAuth">Whether an authenticated BFF session is required.</param>
    public sealed record ApiEndpoint(string Method, string Path, string Description, bool RequiresAuth);
}
