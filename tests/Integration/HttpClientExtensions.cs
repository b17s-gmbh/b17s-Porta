using System.Net;

using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Integration;

/// <summary>
/// Test-only HTTP helpers shared across the integration suites.
/// </summary>
internal static class HttpClientExtensions
{
    /// <summary>
    /// Drives the three-step OIDC code flow (BFF /bff/login → IdP /authorize → BFF
    /// callback) against the supplied <paramref name="idp"/>. Returns a cookie-jar
    /// equipped <see cref="HttpClient"/> bound to <paramref name="bff"/> that
    /// subsequent calls reuse so they're "logged in".
    /// </summary>
    /// <remarks>
    /// The framework's OIDC handler issues a correlation cookie on the initial
    /// challenge and validates it on callback. We extract that cookie from the
    /// 302 and replay it on the callback to satisfy the framework.
    /// </remarks>
    public static async Task<HttpClient> LoginAsync(this IHost bff, FakeIdp idp, CancellationToken cancellationToken = default)
    {
        var client = bff.CreateAuthenticatedClient();

        // Step 1: BFF login → 302 to IdP authorize, carrying the correlation cookie.
        var loginResponse = await client.GetAsync("/bff/login", cancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        var authorizeUrl = loginResponse.Headers.Location!;
        var correlationCookies = ExtractCookies(loginResponse);

        // Step 2: Drive IdP authorize → 302 back to BFF callback with code+state.
        var idpResponse = await idp.FrontchannelClient.GetAsync(authorizeUrl, cancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, idpResponse.StatusCode);
        var callbackUrl = idpResponse.Headers.Location!;

        // Step 3: BFF callback → exchanges code, sets session cookie.
        var callbackRequest = new HttpRequestMessage(HttpMethod.Get, callbackUrl.PathAndQuery);
        foreach (var cookie in correlationCookies)
        {
            callbackRequest.Headers.Add("Cookie", cookie);
        }
        var callbackResponse = await client.SendAsync(callbackRequest, cancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, callbackResponse.StatusCode);

        var sessionCookies = ExtractCookies(callbackResponse);
        var authenticated = bff.CreateAuthenticatedClient();
        foreach (var cookie in sessionCookies)
        {
            authenticated.DefaultRequestHeaders.Add("Cookie", cookie);
        }
        return authenticated;
    }

    /// <summary>
    /// Test-server client that doesn't auto-follow redirects (so tests can
    /// observe 302s) and uses <c>http://localhost</c> as the base address.
    /// </summary>
    public static HttpClient CreateAuthenticatedClient(this IHost host)
    {
        var server = host.GetTestServer();
        var handler = server.CreateHandler();
        return new HttpClient(new NoRedirectHandler(handler))
        {
            BaseAddress = new Uri("http://localhost"),
        };
    }

    /// <summary>
    /// Logs in via the OIDC code flow and returns a client backed by a real
    /// <see cref="CookieContainer"/> seeded with the session auth cookie. Subsequent calls then
    /// capture and replay the ASP.NET session cookie (issued on the first request that touches
    /// <c>HttpContext.Session</c>), which suites asserting on per-session caching depend on.
    /// </summary>
    /// <remarks>
    /// The login hops reuse the manual, path-agnostic correlation-cookie replay from
    /// <see cref="LoginAsync"/>; a strict <see cref="CookieContainer"/> rejects the OIDC
    /// correlation cookie on path grounds. Only the post-login traffic needs the jar.
    /// </remarks>
    public static async Task<HttpClient> LoginWithCookieJarAsync(this IHost bff, FakeIdp idp, CancellationToken cancellationToken = default)
    {
        var loginClient = bff.CreateAuthenticatedClient();

        var loginResponse = await loginClient.GetAsync("/bff/login", cancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);
        var authorizeUrl = loginResponse.Headers.Location!;
        var correlationCookies = ExtractCookies(loginResponse);

        var idpResponse = await idp.FrontchannelClient.GetAsync(authorizeUrl, cancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, idpResponse.StatusCode);
        var callbackUrl = idpResponse.Headers.Location!;

        var callbackRequest = new HttpRequestMessage(HttpMethod.Get, callbackUrl.PathAndQuery);
        foreach (var cookie in correlationCookies)
        {
            callbackRequest.Headers.Add("Cookie", cookie);
        }
        var callbackResponse = await loginClient.SendAsync(callbackRequest, cancellationToken);
        Assert.Equal(HttpStatusCode.Redirect, callbackResponse.StatusCode);

        // Seed a jar with the session auth cookie(s) so the cookie-aware client is authenticated,
        // then let it capture the session cookie on the first request that writes to the session.
        var jar = new CookieContainer();
        var baseUri = new Uri("http://localhost");
        foreach (var cookie in ExtractCookies(callbackResponse))
        {
            var separatorIndex = cookie.IndexOf('=', StringComparison.Ordinal);
            if (separatorIndex <= 0)
            {
                continue;
            }
            jar.Add(baseUri, new Cookie(cookie[..separatorIndex], cookie[(separatorIndex + 1)..]));
        }

        return bff.CreateCookieJarClient(jar);
    }

    /// <summary>
    /// Test-server client with a <see cref="CookieContainer"/> layered over the (non-redirecting)
    /// TestServer handler, so Set-Cookie responses are captured and replayed automatically.
    /// </summary>
    public static HttpClient CreateCookieJarClient(this IHost host, CookieContainer jar)
    {
        var server = host.GetTestServer();
        var handler = new CookieJarHandler(server.CreateHandler(), jar);
        return new HttpClient(handler)
        {
            BaseAddress = new Uri("http://localhost"),
        };
    }

    private static List<string> ExtractCookies(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            return [];
        }

        var cookies = new List<string>();
        foreach (var raw in setCookies)
        {
            var nameValue = raw.Split(';', 2)[0];
            cookies.Add(nameValue);
        }
        return cookies;
    }

    private sealed class NoRedirectHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => base.SendAsync(request, cancellationToken);
    }

    /// <summary>
    /// Adds <see cref="CookieContainer"/> semantics over the TestServer handler, which by itself
    /// neither stores nor replays cookies. Does not auto-follow redirects.
    /// </summary>
    private sealed class CookieJarHandler(HttpMessageHandler inner, CookieContainer jar) : DelegatingHandler(inner)
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            var cookieHeader = jar.GetCookieHeader(uri);
            if (!string.IsNullOrEmpty(cookieHeader))
            {
                request.Headers.Remove("Cookie");
                request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
            }

            var response = await base.SendAsync(request, cancellationToken);

            if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var setCookie in setCookies)
                {
                    jar.SetCookies(uri, setCookie);
                }
            }

            return response;
        }
    }
}
