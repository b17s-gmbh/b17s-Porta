using System.Net;

using b17s.Porta.Transformers;

namespace b17s.Porta.Tests.Spec;

/// <summary>
/// Spec §2.2 — RawBackendResult transport-success semantics and BackendObjectResult factories.
/// </summary>
public class RawAndObjectResultContractTests
{
    // ----- RawBackendResult: IsSuccess == transport succeeded, NOT 2xx (§2.2) -----

    [Fact]
    public void RawSuccess_With401Response_StillReportsSuccess()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        var result = RawBackendResult.Success(response);

        Assert.True(result.IsSuccess);          // transport succeeded
        Assert.Same(response, result.Response); // caller inspects Response.StatusCode themselves
    }

    [Fact]
    public void RawSuccess_With500Response_StillReportsSuccess()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.InternalServerError);
        var result = RawBackendResult.Success(response);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Response);
    }

    // ----- BackendObjectResult (struct) factories (§2.2) -----

    [Fact]
    public void ObjectSuccess_DefaultsTo200_NoError()
    {
        var r = BackendObjectResult.Success("payload");

        Assert.True(r.IsSuccess);
        Assert.Equal(200, r.StatusCode);
        Assert.Equal(BackendErrorType.None, r.ErrorType);
        Assert.Equal("payload", r.Value);
    }

    [Fact]
    public void ObjectFailure_CarriesStatusErrorType()
    {
        var r = BackendObjectResult.Failure(503, "boom", BackendErrorType.ServerError);

        Assert.False(r.IsSuccess);
        Assert.Equal(503, r.StatusCode);
        Assert.Equal(BackendErrorType.ServerError, r.ErrorType);
    }

    // Note: BackendObjectResult (struct) exposes only Success/Failure — it does not carry the named
    // AuthenticationFailure/NetworkFailure/etc. factories that the generic BackendResult<T> does.
}
