using b17s.Porta.Transformers;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Covers the two built-in <see cref="IBackendErrorMapper"/> implementations. The default
/// mapper rewrites backend 401/403 to 502 so a misconfigured BFF-to-backend credential never
/// causes the frontend to sign the user out — that contract is the entire reason this
/// abstraction exists, so each branch needs an explicit lock-in.
/// </summary>
public sealed class BackendErrorMapperTests
{
    private static BackendRequest Request(string url = "https://backend.test/resource") => new()
    {
        Method = "GET",
        Url = url,
    };

    public sealed class Default
    {
        [Fact]
        public void Maps401_To502_WithAuthenticationMessage()
        {
            var (status, message) = new DefaultBackendErrorMapper()
                .MapError(401, "Unauthorized from backend", Request());

            Assert.Equal(502, status);
            Assert.Equal("Backend service authentication failed", message);
        }

        [Fact]
        public void Maps403_To502_WithAuthorizationMessage()
        {
            var (status, message) = new DefaultBackendErrorMapper()
                .MapError(403, "Forbidden from backend", Request());

            Assert.Equal(502, status);
            Assert.Equal("Backend service authorization failed", message);
        }

        [Theory]
        [InlineData(400)]
        [InlineData(404)]
        [InlineData(409)]
        [InlineData(418)]
        [InlineData(500)]
        [InlineData(502)]
        [InlineData(503)]
        [InlineData(504)]
        public void NonAuthStatus_PassesThroughWithBackendMessage(int statusCode)
        {
            var (status, message) = new DefaultBackendErrorMapper()
                .MapError(statusCode, "raw backend error", Request());

            Assert.Equal(statusCode, status);
            Assert.Equal("raw backend error", message);
        }

        [Fact]
        public void NullBackendError_FallsBackToGenericMessage()
        {
            var (status, message) = new DefaultBackendErrorMapper()
                .MapError(500, backendError: null, Request());

            Assert.Equal(500, status);
            Assert.Equal("Backend request failed", message);
        }

        [Fact]
        public void Maps401_With_NullBackendError_StillReturnsFixedMessage()
        {
            // The 401/403 messages are framework-owned strings, not the backend's. Even when
            // the backend gives us nothing, we should still produce the canonical text so
            // logs are consistent.
            var (status, message) = new DefaultBackendErrorMapper()
                .MapError(401, backendError: null, Request());

            Assert.Equal(502, status);
            Assert.Equal("Backend service authentication failed", message);
        }
    }

    public sealed class PassThrough
    {
        [Theory]
        [InlineData(401)]
        [InlineData(403)]
        [InlineData(404)]
        [InlineData(500)]
        [InlineData(599)]
        public void EveryStatus_IsForwardedUnchanged(int statusCode)
        {
            var (status, message) = new PassThroughBackendErrorMapper()
                .MapError(statusCode, "backend said no", Request());

            Assert.Equal(statusCode, status);
            Assert.Equal("backend said no", message);
        }

        [Fact]
        public void NullBackendError_FallsBackToGenericMessage()
        {
            var (status, message) = new PassThroughBackendErrorMapper()
                .MapError(500, backendError: null, Request());

            Assert.Equal(500, status);
            Assert.Equal("Backend request failed", message);
        }

        [Fact]
        public void Maps401_PassesThrough_NotRewritten()
        {
            // Regression guard: PassThrough explicitly opts out of the safety rewrite. If a
            // future refactor accidentally pushes the 401→502 mapping into the interface
            // default, this assertion fails loudly.
            var (status, _) = new PassThroughBackendErrorMapper()
                .MapError(401, "Unauthorized", Request());

            Assert.Equal(401, status);
        }
    }
}
