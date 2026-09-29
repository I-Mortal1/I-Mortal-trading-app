using IMortal.TrustBroker.Providers;
using IMortal.TrustBroker.Registration;
using IMortal.TrustBroker.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class F21UserEnrollmentTests
{
    private const string PolicyVersion = "F14-V1";
    private const string PolicySha256 =
        "PUBLIC_DIGEST_REMOVED";

    private sealed class StubTrustProvider : ITrustProvider
    {
        private readonly TrustDetectionResult _detection;

        public StubTrustProvider(TrustDetectionResult detection)
        {
            _detection = detection;
        }

        public string ProviderId => _detection.ProviderId;
        public bool IsAvailable() => true;
        public TrustDetectionResult Detect() => _detection;

        public TrustProviderCapabilities GetCapabilities() =>
            TrustProviderCapabilities.Detection;

        public Task<TrustIdentityResult> EnrollAsync(
            AuthorizationRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new TrustIdentityResult(
                false, null, "TEST_ENROLLMENT_DISABLED"));

        public Task<TrustOperationResult> AuthorizeAsync(
            AuthorizationRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new TrustOperationResult(
                false, "TEST_AUTHORIZATION_DISABLED", null));

        public Task<TrustOperationResult> AttestAsync(
            AuthorizationRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new TrustOperationResult(
                false, "TEST_ATTESTATION_DISABLED", null));

        public Task<TrustOperationResult> SignAsync(
            AuthorizationRequest request,
            ReadOnlyMemory<byte> data,
            CancellationToken cancellationToken) =>
            Task.FromResult(new TrustOperationResult(
                false, "TEST_SIGNING_DISABLED", null));

        public Task<TrustOperationResult> RevokeAsync(
            AuthorizationRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new TrustOperationResult(
                false, "TEST_REVOCATION_DISABLED", null));
    }

    private static UserRegistrationRequest ValidRequest(
        string userId = "test-user-001") =>
        new(userId, PolicyVersion, PolicySha256);

    private static SecurityEnrollmentService Service(
        TrustDetectionResult detection) =>
        new(new StubTrustProvider(detection));

    private static TrustDetectionResult HardwareReady() =>
        new(
            TrustProviderState.HardwareReady,
            "test-provider",
            true,
            true);

    [TestMethod]
    public void IdentityDerivation_IsSha256Sized()
    {
        var id = SecurityIdentityDeriver.Derive(
            "test-domain", "test-value");

        Assert.AreEqual(64, id.Length);
        Assert.IsTrue(id.All(Uri.IsHexDigit));
    }

    [TestMethod]
    public void IdentityDerivation_IsDeterministic()
    {
        var a = SecurityIdentityDeriver.Derive(
            "test-domain", "test-value");
        var b = SecurityIdentityDeriver.Derive(
            "test-domain", "test-value");

        Assert.AreEqual(a, b);
    }

    [TestMethod]
    public void IdentityDerivation_IsDomainSeparated()
    {
        var storage = SecurityIdentityDeriver.Derive(
            "storage", "same-value");
        var key = SecurityIdentityDeriver.Derive(
            "key", "same-value");

        Assert.AreNotEqual(storage, key);
    }

    [TestMethod]
    public void Registration_ProducesHashedSecurityIdentity()
    {
        var profile = Service(HardwareReady()).Register(
            ValidRequest());

        Assert.AreEqual(64, profile.SecurityInstanceId.Length);
        Assert.IsTrue(profile.SecurityInstanceId.All(Uri.IsHexDigit));
        Assert.AreEqual(64, profile.RegistrationNonceHash.Length);
        Assert.IsTrue(profile.RegistrationNonceHash.All(Uri.IsHexDigit));
    }

    [TestMethod]
    public void Registration_PropagatesFrozenPolicyIdentity()
    {
        var profile = Service(HardwareReady()).Register(
            ValidRequest());

        Assert.AreEqual(PolicyVersion, profile.SecurityPolicyVersion);
        Assert.AreEqual(PolicySha256, profile.SecurityPolicySha256);
    }

    [TestMethod]
    public void Registration_PropagatesProviderDetection()
    {
        var profile = Service(HardwareReady()).Register(
            ValidRequest());

        Assert.AreEqual("test-provider", profile.ProviderId);
        Assert.AreEqual(
            TrustProviderState.HardwareReady,
            profile.TrustState);
        Assert.IsTrue(profile.HardwareBacked);
        Assert.IsTrue(profile.NonExportableKeysSupported);
        Assert.AreEqual(
            SecurityEnrollmentState.HardwareReady,
            profile.EnrollmentState);
    }

    [TestMethod]
    public void Registration_NeverAuthorizesProduction()
    {
        var profile = Service(HardwareReady()).Register(
            ValidRequest());

        Assert.IsFalse(profile.ProductionAuthorized);
        Assert.IsTrue(
            profile.EnrollmentState <
            SecurityEnrollmentState.ProductionAuthorized);

        SecurityEnrollmentInvariants.AssertSafe(profile);
    }

    [TestMethod]
    public void Registration_UnavailableProvider_RemainsRegistrationAccepted()
    {
        var detection = new TrustDetectionResult(
            TrustProviderState.Unavailable,
            "test-provider",
            false,
            false);

        var profile = Service(detection).Register(
            ValidRequest());

        Assert.AreEqual(
            SecurityEnrollmentState.RegistrationAccepted,
            profile.EnrollmentState);
        Assert.IsFalse(profile.ProductionAuthorized);
    }

    [TestMethod]
    public void Registration_RejectsMissingUserId()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            Service(HardwareReady()).Register(
                ValidRequest("")));
    }

    [TestMethod]
    public void Registration_RejectsOversizedUserId()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            Service(HardwareReady()).Register(
                ValidRequest(new string('x', 257))));
    }

    [TestMethod]
    public void Registration_RejectsMissingPolicyVersion()
    {
        var request = new UserRegistrationRequest(
            "test-user-001",
            "",
            PolicySha256);

        Assert.ThrowsExactly<ArgumentException>(() =>
            Service(HardwareReady()).Register(request));
    }

    [TestMethod]
    public void Registration_RejectsShortPolicyHash()
    {
        var request = new UserRegistrationRequest(
            "test-user-001",
            PolicyVersion,
            "deadbeef");

        Assert.ThrowsExactly<ArgumentException>(() =>
            Service(HardwareReady()).Register(request));
    }

    [TestMethod]
    public void Registration_RejectsNonHexPolicyHash()
    {
        var request = new UserRegistrationRequest(
            "test-user-001",
            PolicyVersion,
            new string('g', 64));

        Assert.ThrowsExactly<ArgumentException>(() =>
            Service(HardwareReady()).Register(request));
    }

    [TestMethod]
    public void Registration_RejectsNullRequest()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            Service(HardwareReady()).Register(null!));
    }
}
