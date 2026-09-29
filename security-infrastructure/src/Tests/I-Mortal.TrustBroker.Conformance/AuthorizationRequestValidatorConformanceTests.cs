using IMortal.TrustBroker.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class AuthorizationRequestValidatorConformanceTests
{
    private static readonly DateTimeOffset Now =
        new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static AuthorizationRequest ValidRequest() =>
        new(
            RequestId: "request-001",
            Operation: "sign",
            DeviceIdentity: "device-001",
            Nonce: "nonce-001",
            ExpiresAt: Now.AddMinutes(5),
            PolicyVersion: "policy-v1",
            AuthorizationState: "requested");

    [TestMethod]
    public void Null_Request_Is_Rejected()
    {
        var result =
            AuthorizationRequestValidator.Validate(null, Now);

        Assert.IsFalse(result.Success);
        Assert.AreEqual("REQUEST_REQUIRED", result.ErrorCode);
    }

    [TestMethod]
    public void Valid_Request_Is_Accepted()
    {
        var result =
            AuthorizationRequestValidator.Validate(
                ValidRequest(),
                Now);

        Assert.IsTrue(result.Success);
        Assert.IsNull(result.ErrorCode);
    }

    [TestMethod]
    public void Missing_RequestId_Is_Rejected()
    {
        var request = ValidRequest() with { RequestId = " " };

        AssertRejected(
            request,
            "REQUEST_ID_REQUIRED");
    }

    [TestMethod]
    public void Missing_Operation_Is_Rejected()
    {
        var request = ValidRequest() with { Operation = "" };

        AssertRejected(
            request,
            "OPERATION_REQUIRED");
    }

    [TestMethod]
    public void Missing_DeviceIdentity_Is_Rejected()
    {
        var request =
            ValidRequest() with { DeviceIdentity = " " };

        AssertRejected(
            request,
            "DEVICE_IDENTITY_REQUIRED");
    }

    [TestMethod]
    public void Missing_Nonce_Is_Rejected()
    {
        var request = ValidRequest() with { Nonce = "" };

        AssertRejected(
            request,
            "NONCE_REQUIRED");
    }

    [TestMethod]
    public void Missing_PolicyVersion_Is_Rejected()
    {
        var request =
            ValidRequest() with { PolicyVersion = " " };

        AssertRejected(
            request,
            "POLICY_VERSION_REQUIRED");
    }

    [TestMethod]
    public void Missing_AuthorizationState_Is_Rejected()
    {
        var request =
            ValidRequest() with { AuthorizationState = "" };

        AssertRejected(
            request,
            "AUTHORIZATION_STATE_REQUIRED");
    }

    [TestMethod]
    public void Expired_Request_Is_Rejected()
    {
        var request =
            ValidRequest() with
            {
                ExpiresAt = Now.AddTicks(-1)
            };

        AssertRejected(
            request,
            "REQUEST_EXPIRED");
    }

    [TestMethod]
    public void Request_Expiring_Exactly_Now_Is_Rejected()
    {
        var request =
            ValidRequest() with
            {
                ExpiresAt = Now
            };

        AssertRejected(
            request,
            "REQUEST_EXPIRED");
    }

    [TestMethod]
    public void Future_Request_Is_Not_Expired()
    {
        var request =
            ValidRequest() with
            {
                ExpiresAt = Now.AddTicks(1)
            };

        var result =
            AuthorizationRequestValidator.Validate(
                request,
                Now);

        Assert.IsTrue(result.Success);
        Assert.IsNull(result.ErrorCode);
    }

    private static void AssertRejected(
        AuthorizationRequest request,
        string expectedCode)
    {
        var result =
            AuthorizationRequestValidator.Validate(
                request,
                Now);

        Assert.IsFalse(result.Success);
        Assert.AreEqual(
            expectedCode,
            result.ErrorCode);
    }
}
