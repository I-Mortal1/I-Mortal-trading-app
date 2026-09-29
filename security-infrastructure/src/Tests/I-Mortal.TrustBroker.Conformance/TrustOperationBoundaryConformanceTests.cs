using IMortal.TrustBroker.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class TrustOperationBoundaryConformanceTests
{
    private static readonly DateTimeOffset Now =
        new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static AuthorizationRequest ValidRequest() =>
        new(
            RequestId: "request-boundary-001",
            Operation: "sign",
            DeviceIdentity: "device-001",
            Nonce: "nonce-boundary-001",
            ExpiresAt: Now.AddMinutes(5),
            PolicyVersion: "policy-v1",
            AuthorizationState: "requested");

    [TestMethod]
    public void Null_Request_Fails_Before_Dispatch()
    {
        var result =
            TrustOperationBoundary.ValidateForDispatch(
                null,
                Now);

        Assert.IsFalse(result.Success);
        Assert.AreEqual(
            "REQUEST_REQUIRED",
            result.ResultCode);
    }

    [TestMethod]
    public void Invalid_Request_Fails_Before_Dispatch()
    {
        var request =
            ValidRequest() with
            {
                Nonce = ""
            };

        var result =
            TrustOperationBoundary.ValidateForDispatch(
                request,
                Now);

        Assert.IsFalse(result.Success);
        Assert.AreEqual(
            "NONCE_REQUIRED",
            result.ResultCode);
    }

    [TestMethod]
    public void Expired_Request_Fails_Before_Dispatch()
    {
        var request =
            ValidRequest() with
            {
                ExpiresAt = Now
            };

        var result =
            TrustOperationBoundary.ValidateForDispatch(
                request,
                Now);

        Assert.IsFalse(result.Success);
        Assert.AreEqual(
            "REQUEST_EXPIRED",
            result.ResultCode);
    }

    [TestMethod]
    public void Valid_Request_Remains_Fail_Closed()
    {
        var result =
            TrustOperationBoundary.ValidateForDispatch(
                ValidRequest(),
                Now);

        Assert.IsFalse(result.Success);
        Assert.AreEqual(
            "PROVIDER_DISPATCH_DISABLED",
            result.ResultCode);
    }
}
