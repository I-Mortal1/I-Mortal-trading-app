using IMortal.TrustBroker.Providers;
using IMortal.TrustBroker.Registration;
using IMortal.TrustBroker.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class F22ServerAuthoritativePolicyTests
{
    private const string PolicyVersion = "F22-A-V1";
    private const string PolicySha256 =
        "PUBLIC_DIGEST_REMOVED";

    private sealed class StubProvider : ITrustProvider
    {
        private readonly TrustDetectionResult _detection;

        public StubProvider(TrustDetectionResult detection)
        {
            _detection = detection;
        }

        public string ProviderId => "test-provider";

        public bool IsAvailable() => true;

        public TrustDetectionResult Detect() => _detection;

        public TrustProviderCapabilities GetCapabilities() =>
            TrustProviderCapabilities.Detection;

        public Task<TrustIdentityResult> EnrollAsync(
            AuthorizationRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(
                new TrustIdentityResult(
                    false,
                    null,
                    "TEST_OPERATION_DISABLED"));

        public Task<TrustOperationResult> AuthorizeAsync(
            AuthorizationRequest request,
            CancellationToken cancellationToken) =>
            Disabled();

        public Task<TrustOperationResult> AttestAsync(
            AuthorizationRequest request,
            CancellationToken cancellationToken) =>
            Disabled();

        public Task<TrustOperationResult> SignAsync(
            AuthorizationRequest request,
            ReadOnlyMemory<byte> data,
            CancellationToken cancellationToken) =>
            Disabled();

        public Task<TrustOperationResult> RevokeAsync(
            AuthorizationRequest request,
            CancellationToken cancellationToken) =>
            Disabled();

        private static Task<TrustOperationResult> Disabled() =>
            Task.FromResult(
                new TrustOperationResult(
                    false,
                    "TEST_OPERATION_DISABLED",
                    null));
    }

    private static TrustDetectionResult HardwareReady() =>
        new(
            TrustProviderState.HardwareReady,
            "test-provider",
            true,
            true);

    private static SecurityPolicyReference Policy() =>
        new(PolicyVersion, PolicySha256);

    private static SecurityEnrollmentService Service() =>
        new(
            new StubProvider(HardwareReady()),
            Policy());

    [TestMethod]
    public void Registration_BindsServerAuthoritativePolicy()
    {
        var profile = Service().Register(
            new UserRegistrationRequest("user-1"));

        Assert.AreEqual(
            PolicyVersion,
            profile.SecurityPolicyVersion);

        Assert.AreEqual(
            PolicySha256,
            profile.SecurityPolicySha256);
    }

    [TestMethod]
    public void RegistrationRequest_ExposesOnlyUserId()
    {
        var properties =
            typeof(UserRegistrationRequest).GetProperties();

        Assert.HasCount(1, properties);
        Assert.AreEqual("UserId", properties[0].Name);
    }

    [TestMethod]
    public void RegistrationRequest_HasNoPolicyVersionProperty()
    {
        Assert.IsNull(
            typeof(UserRegistrationRequest)
                .GetProperty("SecurityPolicyVersion"));
    }

    [TestMethod]
    public void RegistrationRequest_HasNoPolicyHashProperty()
    {
        Assert.IsNull(
            typeof(UserRegistrationRequest)
                .GetProperty("SecurityPolicySha256"));
    }

    [TestMethod]
    public void PolicyReference_RejectsNullVersion()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => new SecurityPolicyReference(
                null!,
                PolicySha256));
    }

    [TestMethod]
    public void PolicyReference_RejectsBlankVersion()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => new SecurityPolicyReference(
                "   ",
                PolicySha256));
    }

    [TestMethod]
    public void PolicyReference_RejectsShortHash()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => new SecurityPolicyReference(
                PolicyVersion,
                "abcd"));
    }

    [TestMethod]
    public void PolicyReference_RejectsUppercaseHash()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => new SecurityPolicyReference(
                PolicyVersion,
                PolicySha256.ToUpperInvariant()));
    }

    [TestMethod]
    public void PolicyReference_RejectsNonHexHash()
    {
        var invalid = new string('g', 64);

        Assert.ThrowsExactly<ArgumentException>(
            () => new SecurityPolicyReference(
                PolicyVersion,
                invalid));
    }

    [TestMethod]
    public void EnrollmentService_RejectsNullPolicy()
    {
        Assert.ThrowsExactly<ArgumentNullException>(
            () => new SecurityEnrollmentService(
                new StubProvider(HardwareReady()),
                null!));
    }

    [TestMethod]
    public void EnrollmentService_RejectsNullProvider()
    {
        Assert.ThrowsExactly<ArgumentNullException>(
            () => new SecurityEnrollmentService(
                null!,
                Policy()));
    }

    [TestMethod]
    public void Registration_NeverAuthorizesProduction()
    {
        var profile = Service().Register(
            new UserRegistrationRequest("user-1"));

        Assert.IsFalse(profile.ProductionAuthorized);
        Assert.IsLessThan(
            (int)SecurityEnrollmentState.ProductionAuthorized,
            (int)profile.EnrollmentState);
    }

    [TestMethod]
    public void Registration_ProducesSha256SizedIdentity()
    {
        var profile = Service().Register(
            new UserRegistrationRequest("user-1"));

        Assert.AreEqual(
            64,
            profile.SecurityInstanceId.Length);
        Assert.AreEqual(
            64,
            profile.RegistrationNonceHash.Length);
    }

    [TestMethod]
    public void Registration_RejectsNullRequest()
    {
        Assert.ThrowsExactly<ArgumentNullException>(
            () => Service().Register(null!));
    }

    [TestMethod]
    public void Registration_RejectsMissingUserId()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => Service().Register(
                new UserRegistrationRequest("")));
    }

    [TestMethod]
    public void Registration_RejectsOversizedUserId()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => Service().Register(
                new UserRegistrationRequest(
                    new string('x', 257))));
    }
}
