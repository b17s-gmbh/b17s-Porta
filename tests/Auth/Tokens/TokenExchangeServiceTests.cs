using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace b17s.Porta.Tests.Auth.Tokens;

public sealed class TokenExchangeServiceTests
{
    [Fact]
    public async Task ExchangeAsync_MissingTokenEndpoint_FailsWithoutHttpCall()
    {
        // Per-API token endpoint must be configured - empty would NRE inside HttpClient.PostAsync.
        var handler = new RecordingHandler(_ => OkExchange());
        var sut = Build(handler);

        var result = await sut.ExchangeAsync(
            "user-token",
            new ApiConfiguration
            {
                ApiPath = "/api/x",
                ClientId = "c",
                ClientSecret = "s",
                TokenEndpoint = "",
            },
            TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(0, handler.Calls);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task ExchangeAsync_MissingClientId_FailsWithoutHttpCall()
    {
        var handler = new RecordingHandler(_ => OkExchange());
        var sut = Build(handler);

        var result = await sut.ExchangeAsync(
            "user-token",
            new ApiConfiguration
            {
                ApiPath = "/api/x",
                ClientId = "",
                ClientSecret = "s",
                TokenEndpoint = "https://idp.test/token",
            },
            TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task ExchangeAsync_MissingClientSecret_FailsWithoutHttpCall()
    {
        // Half-credentials must not leak to the IdP; fail closed instead.
        var handler = new RecordingHandler(_ => OkExchange());
        var sut = Build(handler);

        var result = await sut.ExchangeAsync(
            "user-token",
            new ApiConfiguration
            {
                ApiPath = "/api/x",
                ClientId = "c",
                ClientSecret = "",
                TokenEndpoint = "https://idp.test/token",
            },
            TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task ExchangeAsync_BuildsRfc8693FormBody()
    {
        // RFC 8693: grant_type, subject_token, requested_token_type are required;
        // scope and audience are how the BFF asks for the API-specific token.
        var handler = new RecordingHandler(_ => OkExchange());
        var sut = Build(handler);

        await sut.ExchangeAsync(
            "user-token",
            new ApiConfiguration
            {
                ApiPath = "/api/orders",
                ApiScopes = "orders.read",
                ApiAudience = "orders-api",
                ClientId = "bff-client",
                ClientSecret = "bff-secret",
                TokenEndpoint = "https://idp.test/token",
            },
            TestContext.Current.CancellationToken);

        Assert.Equal("https://idp.test/token", handler.LastRequest!.RequestUri!.ToString());
        Assert.Equal(HttpMethod.Post, handler.LastRequest.Method);
        Assert.Equal("urn:ietf:params:oauth:grant-type:token-exchange", handler.LastForm!["grant_type"]);
        Assert.Equal("bff-client", handler.LastForm["client_id"]);
        Assert.Equal("bff-secret", handler.LastForm["client_secret"]);
        Assert.Equal("user-token", handler.LastForm["subject_token"]);
        Assert.Equal("orders.read", handler.LastForm["scope"]);
        Assert.Equal("orders-api", handler.LastForm["audience"]);
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", handler.LastForm["requested_token_type"]);
    }

    [Fact]
    public async Task ExchangeAsync_EmptyScopeAndAudience_OmitsFormFields()
    {
        // RFC 8693 marks scope and audience OPTIONAL; some IdPs reject empty values,
        // so unconfigured fields must be omitted entirely (not sent as "scope=").
        var handler = new RecordingHandler(_ => OkExchange());
        var sut = Build(handler);

        await sut.ExchangeAsync(
            "user-token",
            new ApiConfiguration
            {
                ApiPath = "/api/x",
                ApiScopes = "",
                ApiAudience = "",
                ClientId = "c",
                ClientSecret = "s",
                TokenEndpoint = "https://idp.test/token",
            },
            TestContext.Current.CancellationToken);

        Assert.NotNull(handler.LastForm);
        Assert.DoesNotContain("scope", handler.LastForm!.Keys);
        Assert.DoesNotContain("audience", handler.LastForm.Keys);
        Assert.Equal("user-token", handler.LastForm["subject_token"]);
    }

    [Fact]
    public async Task ExchangeAsync_SuccessfulResponse_DeserializesIntoResponse()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new TokenExchangeResponse
            {
                AccessToken = "api-token",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            }),
        });
        var sut = Build(handler);

        var result = await sut.ExchangeAsync(
            "user-token",
            BasicApiConfig(),
            TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Response);
        Assert.Equal("api-token", result.Response!.AccessToken);
        Assert.Equal(3600, result.Response.ExpiresIn);
    }

    [Fact]
    public async Task ExchangeAsync_NonSuccessStatus_FailureStringContainsOnlyStatusCode()
    {
        // Failure string is opaque on purpose: IdPs echo back tokens / PII inside their
        // error JSON, and this string surfaces in exception telemetry on the caller side.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("""{"error":"invalid_grant","refresh_token":"leaked-secret-123"}""",
                Encoding.UTF8, "application/json"),
        });
        var sut = Build(handler);

        var result = await sut.ExchangeAsync(
            "user-token",
            BasicApiConfig(),
            TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
        Assert.Contains("400", result.Error!);
        Assert.DoesNotContain("leaked-secret-123", result.Error);
    }

    [Fact]
    public async Task ExchangeAsync_LogIdpErrorBodiesDisabled_FailureStringStaysOpaque()
    {
        // Default LogIdpErrorBodies=false -> the error body that contains sensitive
        // material (refresh tokens, PII) must not surface in the public failure string.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("""{"error":"invalid_grant","refresh_token":"leaked-refresh-token"}""",
                Encoding.UTF8, "application/json"),
        });
        var sut = Build(handler, new PortaCoreOptions { LogIdpErrorBodies = false });

        var result = await sut.ExchangeAsync("user-token", BasicApiConfig(), TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.DoesNotContain("leaked-refresh-token", result.Error!);
        Assert.DoesNotContain("invalid_grant", result.Error!);
    }

    [Fact]
    public async Task ExchangeAsync_NullDeserializedResponse_ReturnsFailure()
    {
        // IdP returned 200 with body that deserializes to null (e.g. empty/null JSON).
        // We must not treat this as success - the caller would get a struct with null Response.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("null", Encoding.UTF8, "application/json"),
        });
        var sut = Build(handler);

        var result = await sut.ExchangeAsync("user-token", BasicApiConfig(), TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task ExchangeAsync_HttpException_ReturnsOpaqueFailure()
    {
        // Exception messages from System.Net.Http sometimes embed the request URL, which
        // carries client_id/scope in some IdP flows. The failure string must stay opaque -
        // the exception itself goes to structured logs.
        var handler = new ThrowingHandler(new HttpRequestException("connect failed to https://idp.test/token?client_id=bff-client"));
        var sut = Build(handler);

        var result = await sut.ExchangeAsync("user-token", BasicApiConfig(), TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
        Assert.DoesNotContain("bff-client", result.Error!);
        Assert.DoesNotContain("idp.test", result.Error);
    }

    [Fact]
    public async Task ExchangeAsync_Cancellation_Propagates_NotSwallowedAsFailure()
    {
        // Caller cancellation (client disconnect / request timeout / host shutdown) must surface as
        // cancellation, not be caught and reported as a generic "Token exchange exception" failure.
        var handler = new ThrowingHandler(new OperationCanceledException());
        var sut = Build(handler);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sut.ExchangeAsync("user-token", BasicApiConfig(), cts.Token));
    }

    [Fact]
    public async Task ExchangeAsync_HttpClientTimeout_StaysFailure_NotMistakenForCancellation()
    {
        // HttpClient.Timeout surfaces as a TaskCanceledException whose token did NOT fire; it stays
        // a (non-propagating) failure rather than being treated as caller cancellation.
        var handler = new ThrowingHandler(new TaskCanceledException("timeout", new TimeoutException()));
        var sut = Build(handler);

        var result = await sut.ExchangeAsync("user-token", BasicApiConfig(), TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
    }

    private const string AccessTokenTypeUrn = "urn:ietf:params:oauth:token-type:access_token";
    private const string RefreshTokenTypeUrn = "urn:ietf:params:oauth:token-type:refresh_token";

    [Fact]
    public async Task ExchangeAsync_WrongIssuedTokenType_ReturnsFailure()
    {
        // RFC 8693: we requested an access token. A compromised/misconfigured STS that hands back
        // a different token type (here: a refresh token) must not have its token cached + forwarded.
        var handler = new RecordingHandler(_ => ExchangeResponse(new TokenExchangeResponse
        {
            AccessToken = "not-an-access-token",
            ExpiresIn = 600,
            TokenType = "Bearer",
            IssuedTokenType = RefreshTokenTypeUrn,
        }));
        var sut = Build(handler);

        var result = await sut.ExchangeAsync("user-token", BasicApiConfig(), TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Response);
    }

    [Fact]
    public async Task ExchangeAsync_CorrectIssuedTokenType_Succeeds()
    {
        var handler = new RecordingHandler(_ => ExchangeResponse(new TokenExchangeResponse
        {
            AccessToken = "api-token",
            ExpiresIn = 600,
            TokenType = "Bearer",
            IssuedTokenType = AccessTokenTypeUrn,
        }));
        var sut = Build(handler);

        var result = await sut.ExchangeAsync("user-token", BasicApiConfig(), TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task ExchangeAsync_AbsentIssuedTokenType_IsTolerated()
    {
        // Not every STS is strictly RFC 8693 compliant; an absent issued_token_type is tolerated
        // (the field is left null by the existing OkExchange()).
        var handler = new RecordingHandler(_ => OkExchange());
        var sut = Build(handler);

        var result = await sut.ExchangeAsync("user-token", BasicApiConfig(), TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task ExchangeAsync_JwtAudienceMismatch_ReturnsFailure()
    {
        // The issued access token is a JWT whose aud is for a different API than we asked for.
        // Forwarding it downstream would be audience confusion - reject it.
        var handler = new RecordingHandler(_ => ExchangeResponse(new TokenExchangeResponse
        {
            AccessToken = CreateJwt(audience: "some-other-api"),
            ExpiresIn = 600,
            TokenType = "Bearer",
            IssuedTokenType = AccessTokenTypeUrn,
        }));
        var sut = Build(handler);

        var result = await sut.ExchangeAsync("user-token", BasicApiConfig(), TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Response);
    }

    [Fact]
    public async Task ExchangeAsync_JwtAudienceMatches_Succeeds()
    {
        var handler = new RecordingHandler(_ => ExchangeResponse(new TokenExchangeResponse
        {
            AccessToken = CreateJwt(audience: "api-audience"),
            ExpiresIn = 600,
            TokenType = "Bearer",
            IssuedTokenType = AccessTokenTypeUrn,
        }));
        var sut = Build(handler);

        var result = await sut.ExchangeAsync("user-token", BasicApiConfig(), TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task ExchangeAsync_OpaqueAccessToken_PassesThrough()
    {
        // Opaque (non-JWT) access tokens cannot be audience-checked here without introspection
        // config; they are passed through rather than rejected.
        var handler = new RecordingHandler(_ => ExchangeResponse(new TokenExchangeResponse
        {
            AccessToken = "opaque-reference-token",
            ExpiresIn = 600,
            TokenType = "Bearer",
            IssuedTokenType = AccessTokenTypeUrn,
        }));
        var sut = Build(handler);

        var result = await sut.ExchangeAsync("user-token", BasicApiConfig(), TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
    }

    private static HttpResponseMessage ExchangeResponse(TokenExchangeResponse response) =>
        new(HttpStatusCode.OK) { Content = JsonContent.Create(response) };

    private static string CreateJwt(string audience)
    {
        // Unsigned JWT - the exchange path only reads the aud claim (the STS link itself is the
        // trust boundary), so no signing credentials are needed.
        var handler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://idp.test",
            Audience = audience,
            Expires = DateTime.UtcNow.AddMinutes(10),
            Claims = new Dictionary<string, object> { ["sub"] = "user-1" },
        };
        return handler.CreateToken(descriptor);
    }

    private static ApiConfiguration BasicApiConfig() => new()
    {
        ApiPath = "/api/x",
        ApiScopes = "api.read",
        ApiAudience = "api-audience",
        ClientId = "c",
        ClientSecret = "s",
        TokenEndpoint = "https://idp.test/token",
    };

    private static HttpResponseMessage OkExchange() => new(HttpStatusCode.OK)
    {
        Content = JsonContent.Create(new TokenExchangeResponse
        {
            AccessToken = "api-token",
            ExpiresIn = 600,
            TokenType = "Bearer",
        }),
    };

    private static TokenExchangeService Build(HttpMessageHandler handler, PortaCoreOptions? core = null)
    {
        var factory = new SingleClientFactory(new HttpClient(handler));
        return new TokenExchangeService(
            factory,
            Options.Create(core ?? new PortaCoreOptions()),
            NullLogger<TokenExchangeService>.Instance);
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public Dictionary<string, string>? LastForm { get; private set; }
        public int Calls { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            LastRequest = request;
            if (request.Content is FormUrlEncodedContent)
            {
                var body = await request.Content.ReadAsStringAsync(cancellationToken);
                LastForm = body.Split('&', StringSplitOptions.RemoveEmptyEntries)
                    .Select(kv => kv.Split('=', 2))
                    .ToDictionary(parts => Uri.UnescapeDataString(parts[0]), parts => Uri.UnescapeDataString(parts[1]));
            }
            return respond(request);
        }
    }

    private sealed class ThrowingHandler(Exception ex) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => throw ex;
    }

    private sealed class SingleClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }
}
