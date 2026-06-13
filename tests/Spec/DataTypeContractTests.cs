using b17s.Porta.Transformers;

namespace b17s.Porta.Tests.Spec;

/// <summary>
/// Spec §2 — Data types, result factories, and enums.
/// Written against specs.md (the behavioral contract), not the implementation.
/// </summary>
public class DataTypeContractTests
{
    // ----- §2.1 BackendRequest defaults -----

    [Fact]
    public void BackendRequest_HasSpecifiedDefaults()
    {
        var req = new BackendRequest { Method = "GET", Url = "https://api.example/resource" };

        Assert.Equal("GET", req.Method);
        Assert.Equal("https://api.example/resource", req.Url);
        Assert.False(req.UseTokenExchange);           // default false
        Assert.Null(req.BackendAuthPolicy);
        Assert.Null(req.BackendName);
        Assert.False(req.EnableRetries);              // default false
        Assert.Equal(3, req.MaxRetryAttempts);        // default 3
    }

    // ----- §2.2 Result factory status codes / error types (BackendResult<T>) -----

    [Fact]
    public void Success_Generic_DefaultsTo200_NoError()
    {
        var r = BackendResult<string>.Success("payload");

        Assert.True(r.IsSuccess);
        Assert.Equal(200, r.StatusCode);
        Assert.Equal(BackendErrorType.None, r.ErrorType);
        Assert.Equal("payload", r.Value);
    }

    [Fact]
    public void Success_Generic_HonorsExplicitStatusCode()
    {
        var r = BackendResult<string>.Success("payload", 201);

        Assert.True(r.IsSuccess);
        Assert.Equal(201, r.StatusCode);
    }

    [Fact]
    public void Failure_Generic_CarriesStatusErrorAndType()
    {
        var r = BackendResult<string>.Failure(503, "boom", BackendErrorType.ServerError);

        Assert.False(r.IsSuccess);
        Assert.Equal(503, r.StatusCode);
        Assert.Equal("boom", r.Error);
        Assert.Equal(BackendErrorType.ServerError, r.ErrorType);
    }

    [Fact]
    public void Failure_Generic_DefaultErrorTypeIsUnknown()
    {
        var r = BackendResult<string>.Failure(418, "teapot");

        Assert.False(r.IsSuccess);
        Assert.Equal(418, r.StatusCode);
        Assert.Equal(BackendErrorType.Unknown, r.ErrorType);
    }

    [Fact]
    public void AuthenticationFailure_Generic_Is401_AuthenticationError()
    {
        var r = BackendResult<string>.AuthenticationFailure("nope");

        Assert.False(r.IsSuccess);
        Assert.Equal(401, r.StatusCode);
        Assert.Equal(BackendErrorType.AuthenticationError, r.ErrorType);
    }

    [Fact]
    public void AuthorizationFailure_Generic_Is403_AuthorizationError()
    {
        var r = BackendResult<string>.AuthorizationFailure("nope");

        Assert.False(r.IsSuccess);
        Assert.Equal(403, r.StatusCode);
        Assert.Equal(BackendErrorType.AuthorizationError, r.ErrorType);
    }

    [Fact]
    public void NetworkFailure_Generic_Is502_NetworkError()
    {
        var r = BackendResult<string>.NetworkFailure("unreachable");

        Assert.False(r.IsSuccess);
        Assert.Equal(502, r.StatusCode);
        Assert.Equal(BackendErrorType.NetworkError, r.ErrorType);
    }

    [Fact]
    public void TimeoutFailure_Generic_Is504_Timeout()
    {
        var r = BackendResult<string>.TimeoutFailure("slow");

        Assert.False(r.IsSuccess);
        Assert.Equal(504, r.StatusCode);
        Assert.Equal(BackendErrorType.Timeout, r.ErrorType);
    }

    // ----- §2.2 Non-generic BackendResult failures -----

    [Fact]
    public void NonGeneric_AuthenticationFailure_Is401()
    {
        var r = BackendResult.AuthenticationFailure("nope");

        Assert.False(r.IsSuccess);
        Assert.Equal(401, r.StatusCode);
        Assert.Equal(BackendErrorType.AuthenticationError, r.ErrorType);
    }

    [Fact]
    public void NonGeneric_TimeoutFailure_Is504()
    {
        var r = BackendResult.TimeoutFailure("slow");

        Assert.False(r.IsSuccess);
        Assert.Equal(504, r.StatusCode);
        Assert.Equal(BackendErrorType.Timeout, r.ErrorType);
    }

    // ----- §2.3 BackendErrorType: ConfigurationError MUST be distinct from AuthenticationError -----

    [Fact]
    public void BackendErrorType_ConfigurationError_IsDistinctFromAuthenticationError()
    {
        Assert.NotEqual(BackendErrorType.ConfigurationError, BackendErrorType.AuthenticationError);
    }

    [Fact]
    public void BackendErrorType_AllSpecifiedMembersExistAndAreDistinct()
    {
        BackendErrorType[] members =
        [
            BackendErrorType.None,
            BackendErrorType.NetworkError,
            BackendErrorType.AuthenticationError,
            BackendErrorType.AuthorizationError,
            BackendErrorType.Timeout,
            BackendErrorType.ServerError,
            BackendErrorType.ClientError,
            BackendErrorType.InvalidResponse,
            BackendErrorType.ConfigurationError,
            BackendErrorType.Unknown,
        ];

        Assert.Equal(members.Length, members.Distinct().Count());
    }

    // ----- §2.4 BackendCallOutcome members exist and are distinct -----

    [Fact]
    public void BackendCallOutcome_FailedAndReturnedNull_AreDistinct()
    {
        Assert.NotEqual(BackendCallOutcome.Failed, BackendCallOutcome.ReturnedNull);
    }

    [Fact]
    public void BackendCallOutcome_AllSpecifiedMembersExistAndAreDistinct()
    {
        BackendCallOutcome[] members =
        [
            BackendCallOutcome.Success,
            BackendCallOutcome.ReturnedNull,
            BackendCallOutcome.Threw,
            BackendCallOutcome.Failed,
        ];

        Assert.Equal(members.Length, members.Distinct().Count());
    }
}
