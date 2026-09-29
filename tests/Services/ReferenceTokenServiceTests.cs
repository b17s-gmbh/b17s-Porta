using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Services;
using b17s.Porta.Tests.Fixtures;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace b17s.Porta.Tests.Services;

public sealed class ReferenceTokenServiceTests
{
    [Fact]
    public async Task IntrospectTokenAsync_AuthorityNotConfigured_ReturnsNull_NoHttpCall()
    {
        // No authority configured -> service must fail closed without dialing anything;
        // calling an empty endpoint URL would otherwise NRE deep in HttpClient.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sut = Build(new ReferenceTokenAuthOptions { Authority = "" }, handler, discovery: null);

        var result = await sut.IntrospectTokenAsync("any-token", TestContext.Current.CancellationToken);

        Assert.Null(result);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task IntrospectTokenAsync_DiscoveryHasNoIntrospectionEndpoint_ReturnsNull_NoHttpCall()
    {
        // RFC 7662 metadata advertises the introspection endpoint via introspection_endpoint.
        // If the IdP doesn't publish it, fail closed - we cannot guess the URL.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var sut = Build(new ReferenceTokenAuthOptions { Authority = "https://idp.test" }, handler, discovery: new OpenIdConnectConfiguration());

        var result = await sut.IntrospectTokenAsync("any-token", TestContext.Current.CancellationToken);

        Assert.Null(result);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task IntrospectTokenAsync_BasicAuth_PercentEncodesClientIdAndSecret()
    {
        // RFC 6749 §2.3.1 mandates percent-encoding both halves of the userid:password
        // pair before forming the Basic credential. A literal ':' or 'space' in the
        // secret would otherwise smuggle into the credential and break parsing on the IdP.
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var options = new ReferenceTokenAuthOptions
        {
            Authority = "https://idp.test",
            ClientId = "client id",
            ClientSecret = "secret:with:colons",
            UseBasicAuthForIntrospection = true,
        };
        var sut = Build(options, captured, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("opaque", TestContext.Current.CancellationToken);

        var auth = captured.LastRequest!.Headers.Authorization;
        Assert.Equal("Basic", auth!.Scheme);
        var raw = Encoding.UTF8.GetString(Convert.FromBase64String(auth.Parameter!));
        // Per RFC the encoded pair is "client%20id:secret%3Awith%3Acolons", not the raw values.
        Assert.Equal("client%20id:secret%3Awith%3Acolons", raw);
    }

    [Fact]
    public async Task IntrospectTokenAsync_BodyCredentials_SendsClientIdAndSecretInForm()
    {
        // UseBasicAuthForIntrospection=false -> credentials in the form body, no Authorization header.
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var options = new ReferenceTokenAuthOptions
        {
            Authority = "https://idp.test",
            ClientId = "client-id",
            ClientSecret = "secret",
            UseBasicAuthForIntrospection = false,
        };
        var sut = Build(options, captured, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("opaque", TestContext.Current.CancellationToken);

        Assert.Null(captured.LastRequest!.Headers.Authorization);
        Assert.Equal("client-id", captured.LastForm!["client_id"]);
        Assert.Equal("secret", captured.LastForm["client_secret"]);
    }

    [Fact]
    public async Task IntrospectTokenAsync_OmitsCredentials_WhenClientIdOrSecretMissing()
    {
        // Public client style (introspection guarded by network ACL, no client auth):
        // do not send half-credentials, and do not send a Basic header with empty fields.
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var options = new ReferenceTokenAuthOptions
        {
            Authority = "https://idp.test",
            ClientId = "client-id",
            ClientSecret = "", // intentionally absent
            UseBasicAuthForIntrospection = true,
        };
        var sut = Build(options, captured, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("opaque", TestContext.Current.CancellationToken);

        Assert.Null(captured.LastRequest!.Headers.Authorization);
        Assert.False(captured.LastForm!.ContainsKey("client_id"));
        Assert.False(captured.LastForm.ContainsKey("client_secret"));
    }

    [Fact]
    public async Task IntrospectTokenAsync_SendsTokenAndOptionalHint_InFormBody()
    {
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var options = new ReferenceTokenAuthOptions
        {
            Authority = "https://idp.test",
            TokenTypeHint = "access_token",
        };
        var sut = Build(options, captured, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("the-opaque-token", TestContext.Current.CancellationToken);

        Assert.Equal("the-opaque-token", captured.LastForm!["token"]);
        Assert.Equal("access_token", captured.LastForm["token_type_hint"]);
    }

    [Fact]
    public async Task IntrospectTokenAsync_OmitsTokenTypeHint_WhenNotConfigured()
    {
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var options = new ReferenceTokenAuthOptions
        {
            Authority = "https://idp.test",
            TokenTypeHint = null,
        };
        var sut = Build(options, captured, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);

        Assert.False(captured.LastForm!.ContainsKey("token_type_hint"));
    }

    [Fact]
    public async Task IntrospectTokenAsync_Non2xxResponse_ReturnsNull()
    {
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("""{"error":"invalid_token"}""", Encoding.UTF8, "application/json"),
        });
        var sut = Build(new ReferenceTokenAuthOptions { Authority = "https://idp.test" }, handler, WithIntrospectionEndpoint());

        var result = await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    [Fact]
    public async Task IntrospectTokenAsync_ActiveResponse_MapsCoreClaims()
    {
        var handler = new RecordingHandler(_ => Ok(new IntrospectionResponse
        {
            Active = true,
            Sub = "user-42",
            ClientId = "the-client",
            Username = "alice",
            Scope = "read write",
            TokenType = "Bearer",
            Iss = "https://idp.test",
            Exp = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds(),
            Jti = "jti-1",
            Aud = ["the-bff"],
        }));
        var sut = Build(new ReferenceTokenAuthOptions { Authority = "https://idp.test" }, handler, WithIntrospectionEndpoint());

        var result = await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.True(result!.IsActive);
        Assert.Equal("user-42", result.Claims["sub"]);
        Assert.Equal("the-client", result.Claims["client_id"]);
        Assert.Equal("alice", result.Claims["username"]);
        Assert.Equal("read write", result.Claims["scope"]);
        Assert.Equal("Bearer", result.Claims["token_type"]);
        Assert.Equal("https://idp.test", result.Claims["iss"]);
        Assert.Equal("jti-1", result.Claims["jti"]);
        Assert.Equal("the-bff", result.Claims["aud"]); // single-value stored bare
        Assert.NotNull(result.ExpiresAt);
    }

    [Fact]
    public async Task IntrospectTokenAsync_MultiAudience_StoresAsJsonArray()
    {
        // Multi-aud preserves order in JSON-array form so the validator can deterministically
        // match against ValidAudiences without string-prefix sniffing.
        var handler = new RecordingHandler(_ => Ok(new IntrospectionResponse
        {
            Active = true,
            Aud = ["bff-a", "bff-b"],
        }));
        var sut = Build(new ReferenceTokenAuthOptions { Authority = "https://idp.test" }, handler, WithIntrospectionEndpoint());

        var result = await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        var parsed = JsonSerializer.Deserialize<string[]>(result!.Claims["aud"]);
        Assert.Equal(["bff-a", "bff-b"], parsed!);
    }

    [Fact]
    public async Task IntrospectTokenAsync_InactiveResponse_ReturnsActiveFalse()
    {
        // An "active":false response is success-with-no-token, distinct from a transport error;
        // the caller still gets a result so negative caching can kick in.
        var handler = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = false }));
        var sut = Build(new ReferenceTokenAuthOptions { Authority = "https://idp.test" }, handler, WithIntrospectionEndpoint());

        var result = await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.False(result!.IsActive);
    }

    [Fact]
    public async Task IntrospectTokenAsync_AdditionalClaimsCopiedToResult()
    {
        // Custom claims (groups, roles, tenant_id, ...) come through JsonExtensionData
        // and must be projected into the result Dictionary as their JSON string form.
        var handler = new RecordingHandler(req =>
        {
            var json = """{"active":true,"sub":"u","department":"eng","is_admin":true,"missing":null}""";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
        });
        var sut = Build(new ReferenceTokenAuthOptions { Authority = "https://idp.test" }, handler, WithIntrospectionEndpoint());

        var result = await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.Equal("eng", result!.Claims["department"]);
        Assert.Equal("True", result.Claims["is_admin"]);
        Assert.Equal(string.Empty, result.Claims["missing"]); // null -> empty string
    }

    [Fact]
    public async Task IntrospectTokenAsync_OversizedResponseBody_RejectedReturnsNull()
    {
        // Robustness: a compromised or buggy IdP must not be able to exhaust memory with an
        // unbounded introspection response. Bodies past the internal cap are rejected.
        var huge = "{\"active\":true,\"sub\":\"u\",\"pad\":\"" + new string('x', 128 * 1024) + "\"}";
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(huge, Encoding.UTF8, "application/json"),
        });
        var sut = Build(new ReferenceTokenAuthOptions { Authority = "https://idp.test" }, handler, WithIntrospectionEndpoint());

        var result = await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    [Fact]
    public async Task IntrospectTokenAsync_PostsToConfiguredIntrospectionEndpoint()
    {
        var handler = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var sut = Build(new ReferenceTokenAuthOptions { Authority = "https://idp.test" }, handler, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);

        Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
        Assert.Equal("https://idp.test/connect/introspect", handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task IntrospectTokenAsync_OptionsMonitor_PicksUpReloadedValues()
    {
        // optionsMonitor.CurrentValue is read per call, so rotating the secret without a
        // restart should be reflected in the next introspection request.
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var monitor = new MutableOptionsMonitor<ReferenceTokenAuthOptions>(new ReferenceTokenAuthOptions
        {
            Authority = "https://idp.test",
            ClientId = "client",
            ClientSecret = "secret-v1",
            UseBasicAuthForIntrospection = false,
        });
        var sut = BuildWithMonitor(monitor, captured, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);
        Assert.Equal("secret-v1", captured.LastForm!["client_secret"]);

        monitor.Current = new ReferenceTokenAuthOptions
        {
            Authority = "https://idp.test",
            ClientId = "client",
            ClientSecret = "secret-v2",
            UseBasicAuthForIntrospection = false,
        };

        await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);
        Assert.Equal("secret-v2", captured.LastForm!["client_secret"]);
    }

    [Fact]
    public async Task IntrospectTokenAsync_LogIdpErrorBodiesToggle_TakesEffectWithoutRestart()
    {
        // PortaCoreOptions is read via IOptionsMonitor.CurrentValue per call (the service is
        // a singleton), so flipping LogIdpErrorBodies - documented as a temporary debugging
        // switch - through an appsettings.json reload must apply without a process restart.
        var handler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("idp-error-detail", Encoding.UTF8, "application/json"),
        });
        var coreMonitor = new MutableOptionsMonitor<PortaCoreOptions>(
            new PortaCoreOptions { LogIdpErrorBodies = false });
        var logger = new ListLogger<ReferenceTokenService>();
        var sut = BuildWithMonitor(
            new MutableOptionsMonitor<ReferenceTokenAuthOptions>(new ReferenceTokenAuthOptions { Authority = "https://idp.test" }),
            handler, WithIntrospectionEndpoint(), coreMonitor, logger);

        await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);
        var redacted = Assert.Single(logger.Entries);
        Assert.Contains("(redacted)", redacted.Message);
        Assert.DoesNotContain("idp-error-detail", redacted.Message);

        coreMonitor.Current = new PortaCoreOptions { LogIdpErrorBodies = true };

        await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);
        Assert.Contains("idp-error-detail", logger.Entries[^1].Message);
    }

    [Fact]
    public async Task IntrospectTokenAsync_PrivateKeyJwt_ZitadelKeyFile_SendsSignedClientAssertion_NoSecret()
    {
        // RFC 7523 §2.2 / Zitadel "Private Key JWT": the client proves possession of the key-file
        // key via a signed assertion in the form body. No Basic header, no secret, and the
        // assertion must verify against the public half of the key with the expected claims.
        using var key = TestSigningKey.Rsa();
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var options = new ReferenceTokenAuthOptions
        {
            Authority = "https://idp.test",
            PrivateKeyJwt = { Key = key.ZitadelKeyFile(clientId: "app@project", keyId: "zkid") },
            UseBasicAuthForIntrospection = true, // ignored in private_key_jwt mode
        };
        var sut = Build(options, captured, WithIntrospectionEndpoint(issuer: "https://idp.test/"));

        await sut.IntrospectTokenAsync("opaque", TestContext.Current.CancellationToken);

        Assert.Null(captured.LastRequest!.Headers.Authorization);
        var form = captured.LastForm!;
        Assert.Equal("opaque", form["token"]);
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form["client_assertion_type"]);
        Assert.False(form.ContainsKey("client_secret"));

        // Audience is the discovered issuer, verbatim (Zitadel requires it).
        var jwt = await key.ValidateAsync(form["client_assertion"], "app@project", "https://idp.test/");
        Assert.Equal("zkid", jwt.Kid);
        Assert.Equal("app@project", jwt.Subject);
    }

    [Fact]
    public async Task IntrospectTokenAsync_PrivateKeyJwt_PemKey_UsesConfiguredClientIdAndAudience()
    {
        // Okta: PEM key + kid from the console, client id from config, and aud must be the URL
        // of the endpoint being called - hence the explicit Audience.
        using var key = TestSigningKey.Rsa();
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var options = new ReferenceTokenAuthOptions
        {
            Authority = "https://idp.test",
            ClientId = "okta-client",
            PrivateKeyJwt =
            {
                Key = key.Pkcs8Pem,
                KeyId = "okta-kid",
                Audience = "https://idp.test/connect/introspect",
            },
        };
        var sut = Build(options, captured, WithIntrospectionEndpoint(issuer: "https://idp.test"));

        await sut.IntrospectTokenAsync("opaque", TestContext.Current.CancellationToken);

        var jwt = await key.ValidateAsync(captured.LastForm!["client_assertion"], "okta-client", "https://idp.test/connect/introspect");
        Assert.Equal("okta-kid", jwt.Kid);
    }

    [Fact]
    public async Task IntrospectTokenAsync_PrivateKeyJwt_AudienceFallsBackToAuthority_WhenNoDiscoveredIssuer()
    {
        using var key = TestSigningKey.Rsa();
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var options = new ReferenceTokenAuthOptions { Authority = "https://idp.test", PrivateKeyJwt = { Key = key.ZitadelKeyFile() } };
        var sut = Build(options, captured, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("opaque", TestContext.Current.CancellationToken);

        var jwt = new JsonWebToken(captured.LastForm!["client_assertion"]);
        Assert.Equal(["https://idp.test"], jwt.Audiences);
    }

    [Fact]
    public async Task IntrospectTokenAsync_PrivateKeyJwt_FreshAssertionPerCall()
    {
        // Each introspection mints a new assertion with a unique jti, so an IdP that enforces
        // single-use assertions (RFC 7523 §3 item 7) never sees a replay.
        using var key = TestSigningKey.Rsa();
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var sut = Build(
            new ReferenceTokenAuthOptions { Authority = "https://idp.test", PrivateKeyJwt = { Key = key.ZitadelKeyFile() } },
            captured, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("a", TestContext.Current.CancellationToken);
        var first = new JsonWebToken(captured.LastForm!["client_assertion"]).Id;
        await sut.IntrospectTokenAsync("b", TestContext.Current.CancellationToken);
        var second = new JsonWebToken(captured.LastForm!["client_assertion"]).Id;

        Assert.NotEqual(first, second);
    }

    [Fact]
    public async Task IntrospectTokenAsync_PrivateKeyJwt_LoadsKeyFromFile()
    {
        using var key = TestSigningKey.Rsa();
        var path = key.WriteTempFile(key.ZitadelKeyFile(keyId: "file-kid"));
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var sut = Build(
            new ReferenceTokenAuthOptions { Authority = "https://idp.test", PrivateKeyJwt = { KeyFile = path } },
            captured, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("opaque", TestContext.Current.CancellationToken);

        Assert.Equal("file-kid", new JsonWebToken(captured.LastForm!["client_assertion"]).Kid);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task IntrospectTokenAsync_PrivateKeyJwt_Unusable_ReturnsNull_NoHttpCall(bool missingFile)
    {
        // A key that fails to load, or a PEM key without a ClientId (e.g. a bad appsettings reload
        // past the startup validator), must fail closed - never an unauthenticated introspection.
        using var key = TestSigningKey.Rsa();
        var handler = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var options = new ReferenceTokenAuthOptions { Authority = "https://idp.test" };
        if (missingFile)
            options.PrivateKeyJwt.KeyFile = Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.json");
        else
            options.PrivateKeyJwt.Key = key.Pkcs8Pem; // no ClientId configured
        var sut = Build(options, handler, WithIntrospectionEndpoint());

        var result = await sut.IntrospectTokenAsync("opaque", TestContext.Current.CancellationToken);

        Assert.Null(result);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task IntrospectTokenAsync_PrivateKeyJwt_ReloadedKey_TakesEffect()
    {
        // The parsed key is cached per configured value; an options reload that swaps the key
        // content is picked up on the next call.
        using var key = TestSigningKey.Rsa();
        var captured = new RecordingHandler(_ => Ok(new IntrospectionResponse { Active = true }));
        var monitor = new MutableOptionsMonitor<ReferenceTokenAuthOptions>(
            new ReferenceTokenAuthOptions { Authority = "https://idp.test", PrivateKeyJwt = { Key = key.ZitadelKeyFile(keyId: "kid-v1") } });
        var sut = BuildWithMonitor(monitor, captured, WithIntrospectionEndpoint());

        await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);
        Assert.Equal("kid-v1", new JsonWebToken(captured.LastForm!["client_assertion"]).Kid);

        monitor.Current = new ReferenceTokenAuthOptions { Authority = "https://idp.test", PrivateKeyJwt = { Key = key.ZitadelKeyFile(keyId: "kid-v2") } };

        await sut.IntrospectTokenAsync("tok", TestContext.Current.CancellationToken);
        Assert.Equal("kid-v2", new JsonWebToken(captured.LastForm!["client_assertion"]).Kid);
    }

    private static OpenIdConnectConfiguration WithIntrospectionEndpoint(string? issuer = null) =>
        new() { Issuer = issuer, AdditionalData = { ["introspection_endpoint"] = "https://idp.test/connect/introspect" } };

    private static HttpResponseMessage Ok(IntrospectionResponse response) =>
        new(HttpStatusCode.OK) { Content = JsonContent.Create(response) };

    private static ReferenceTokenService Build(
        ReferenceTokenAuthOptions options,
        HttpMessageHandler handler,
        OpenIdConnectConfiguration? discovery)
    {
        var monitor = new MutableOptionsMonitor<ReferenceTokenAuthOptions>(options);
        return BuildWithMonitor(monitor, handler, discovery);
    }

    private static ReferenceTokenService BuildWithMonitor(
        IOptionsMonitor<ReferenceTokenAuthOptions> monitor,
        HttpMessageHandler handler,
        OpenIdConnectConfiguration? discovery,
        IOptionsMonitor<PortaCoreOptions>? coreMonitor = null,
        ILogger<ReferenceTokenService>? logger = null)
    {
        var factory = new SingleClientFactory(new HttpClient(handler));
        var discoveryService = new StaticDiscoveryService(discovery);
        var core = coreMonitor ?? new MutableOptionsMonitor<PortaCoreOptions>(new PortaCoreOptions());
        return new ReferenceTokenService(factory, discoveryService, logger ?? NullLogger<ReferenceTokenService>.Instance, monitor, core);
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

    private sealed class SingleClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private sealed class StaticDiscoveryService(OpenIdConnectConfiguration? config) : IDiscoveryService
    {
        public Task<OpenIdConnectConfiguration?> GetConfigurationAsync(string authority, CancellationToken cancellationToken = default)
            => Task.FromResult(config);

        public Task<OpenIdConnectConfiguration?> RefreshConfigurationAsync(string authority, CancellationToken cancellationToken = default)
            => Task.FromResult<OpenIdConnectConfiguration?>(null);
    }

    private sealed class MutableOptionsMonitor<T>(T initial) : IOptionsMonitor<T> where T : class
    {
        public T Current { get; set; } = initial;
        public T CurrentValue => Current;
        public T Get(string? name) => Current;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class ListLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
