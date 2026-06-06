using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Services;

/// <summary>
/// Reference token (opaque token) service that validates tokens via introspection endpoint.
/// Uses named HttpClient with resilience policies.
/// </summary>
public sealed class ReferenceTokenService(
    IHttpClientFactory httpClientFactory,
    IDiscoveryService discoveryService,
    ILogger<ReferenceTokenService> logger,
    IOptionsMonitor<ReferenceTokenAuthOptions> optionsMonitor,
    IOptions<PortaCoreOptions> coreOptions) : IReferenceTokenService
{
    /// <summary>
    /// Named HttpClient identifier for the introspection client.
    /// </summary>
    public const string HttpClientName = "ReferenceTokenIntrospection";

    private readonly PortaCoreOptions _coreOptions = coreOptions.Value;

    public async Task<ReferenceTokenIntrospectionResult?> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        // Read CurrentValue per call so appsettings.json reloads (rotating ClientSecret,
        // adding a ValidAudience) take effect without a process restart.
        var options = optionsMonitor.CurrentValue;

        if (string.IsNullOrEmpty(options.Authority))
        {
            logger.IntrospectionConfigurationMissing();
            return null;
        }

        var config = await discoveryService.GetConfigurationAsync(options.Authority, cancellationToken);
        // Microsoft.IdentityModel binds the discovered "introspection_endpoint" to the strongly-typed
        // IntrospectionEndpoint property, so a document parsed from a real authority never carries it
        // in AdditionalData. Prefer the property; fall back to AdditionalData for hand-built configs.
        var introspectionEndpoint = !string.IsNullOrEmpty(config?.IntrospectionEndpoint)
            ? config.IntrospectionEndpoint
            : config?.AdditionalData.TryGetValue("introspection_endpoint", out var endpoint) == true
                ? endpoint?.ToString()
                : null;

        if (string.IsNullOrEmpty(introspectionEndpoint))
        {
            logger.IntrospectionEndpointNotFound(options.Authority);
            return null;
        }

        var httpClient = httpClientFactory.CreateClient(HttpClientName);
        var request = new HttpRequestMessage(HttpMethod.Post, introspectionEndpoint);

        // Build payload and add client credentials
        var payload = new Dictionary<string, string> { { "token", token } };

        if (!string.IsNullOrEmpty(options.ClientId) && !string.IsNullOrEmpty(options.ClientSecret))
        {
            if (options.UseBasicAuthForIntrospection)
            {
                // RFC 6749 §2.3.1: percent-encode client_id/client_secret before forming the
                // userid:password pair. RFC 7617: encode the pair as UTF-8 before base64.
                var encodedId = Uri.EscapeDataString(options.ClientId);
                var encodedSecret = Uri.EscapeDataString(options.ClientSecret);
                var credentials = Convert.ToBase64String(
                    Encoding.UTF8.GetBytes($"{encodedId}:{encodedSecret}"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            }
            else
            {
                payload["client_id"] = options.ClientId;
                payload["client_secret"] = options.ClientSecret;
            }
        }

        if (!string.IsNullOrEmpty(options.TokenTypeHint))
            payload["token_type_hint"] = options.TokenTypeHint;

        request.Content = new FormUrlEncodedContent(payload);

        var response = await httpClient.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await IdpErrorBodyReader.ReadSafeAsync(response, _coreOptions, cancellationToken);
            logger.IntrospectionFailed((int)response.StatusCode, errorContent);
            return null;
        }

        // Bound the response body. A well-behaved IdP returns a few hundred bytes of JSON;
        // capping the buffered size stops a compromised or buggy authority from exhausting
        // memory with an unbounded introspection response. The error path is already bounded
        // by IdpErrorBodyReader; this closes the same gap on the success path.
        const long MaxIntrospectionResponseBytes = 64 * 1024;
        if (response.Content.Headers.ContentLength is > MaxIntrospectionResponseBytes)
        {
            logger.IntrospectionResponseTooLarge(MaxIntrospectionResponseBytes);
            return null;
        }

        // Defend against a missing or under-reported Content-Length (e.g. chunked transfer):
        // read with a hard cap rather than trusting the advertised length.
        var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using var _ = stream.ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int bytesRead;
        while ((bytesRead = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + bytesRead > MaxIntrospectionResponseBytes)
            {
                logger.IntrospectionResponseTooLarge(MaxIntrospectionResponseBytes);
                return null;
            }
            buffer.Write(chunk, 0, bytesRead);
        }
        buffer.Position = 0;

        // JsonSerializerOptions.Web matches the defaults ReadFromJsonAsync<T> applied previously
        // (camelCase, case-insensitive), so deserialization behavior is unchanged.
        var introspectionResponse = await JsonSerializer.DeserializeAsync<IntrospectionResponse>(
            buffer, JsonSerializerOptions.Web, cancellationToken);

        if (introspectionResponse == null)
            return null;

        return MapToResult(introspectionResponse);
    }

    private static ReferenceTokenIntrospectionResult MapToResult(IntrospectionResponse introspection)
    {
        var claims = new Dictionary<string, string>();

        // Extract standard claims
        if (!string.IsNullOrEmpty(introspection.Sub)) claims["sub"] = introspection.Sub;
        if (!string.IsNullOrEmpty(introspection.ClientId)) claims["client_id"] = introspection.ClientId;
        if (!string.IsNullOrEmpty(introspection.Username)) claims["username"] = introspection.Username;
        if (!string.IsNullOrEmpty(introspection.Scope)) claims["scope"] = introspection.Scope;
        if (!string.IsNullOrEmpty(introspection.TokenType)) claims["token_type"] = introspection.TokenType;
        if (!string.IsNullOrEmpty(introspection.Iss)) claims["iss"] = introspection.Iss;
        if (introspection.Aud is { Length: > 0 } aud)
        {
            // Single-value: store bare. Multi-value: store JSON array form so the validator
            // can round-trip it deterministically without string-prefix sniffing.
            claims["aud"] = aud.Length == 1
                ? aud[0]
                : JsonSerializer.Serialize(aud);
        }
        if (!string.IsNullOrEmpty(introspection.Jti)) claims["jti"] = introspection.Jti;

        // Add additional claims
        if (introspection.AdditionalClaims != null)
        {
            foreach (var claim in introspection.AdditionalClaims)
            {
                claims[claim.Key] = claim.Value.ValueKind != JsonValueKind.Null
                    ? claim.Value.ToString()
                    : string.Empty;
            }
        }

        return new ReferenceTokenIntrospectionResult
        {
            IsActive = introspection.Active,
            ExpiresAt = introspection.Exp.HasValue
                ? DateTimeOffset.FromUnixTimeSeconds(introspection.Exp.Value)
                : null,
            Claims = claims
        };
    }
}

/// <summary>
/// High-performance logging for ReferenceTokenService.
/// </summary>
internal static partial class ReferenceTokenServiceLogging
{
    [LoggerMessage(EventId = 13600, Level = LogLevel.Error,
        Message = "Token introspection failed: Authority not configured")]
    public static partial void IntrospectionConfigurationMissing(this ILogger logger);

    [LoggerMessage(EventId = 13601, Level = LogLevel.Error,
        Message = "Token introspection failed: introspection endpoint not found for authority {Authority}")]
    public static partial void IntrospectionEndpointNotFound(this ILogger logger, string authority);

    [LoggerMessage(EventId = 13602, Level = LogLevel.Warning,
        Message = "Token introspection failed: Status {StatusCode}, Error: {ErrorContent}")]
    public static partial void IntrospectionFailed(this ILogger logger, int statusCode, string errorContent);

    [LoggerMessage(EventId = 13603, Level = LogLevel.Warning,
        Message = "Token introspection failed: response body exceeded the {MaxBytes}-byte limit and was rejected")]
    public static partial void IntrospectionResponseTooLarge(this ILogger logger, long maxBytes);
}
