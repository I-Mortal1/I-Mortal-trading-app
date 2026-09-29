using IMortal.TrustBroker.Providers;
using IMortal.TrustBroker.Providers.Android;
using IMortal.TrustBroker.Providers.IOS;
using IMortal.TrustBroker.Providers.Linux;
using IMortal.TrustBroker.Providers.MacOS;
using IMortal.TrustBroker.Providers.Windows;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class ProviderContractConformanceTests
{
    private static readonly TrustProviderCapabilities ExpectedCapabilities =
        TrustProviderCapabilities.Detection |
        TrustProviderCapabilities.Enrollment |
        TrustProviderCapabilities.Authorization |
        TrustProviderCapabilities.Attestation |
        TrustProviderCapabilities.Signing |
        TrustProviderCapabilities.Revocation;

    private static AuthorizationRequest Request() =>
        new(
            RequestId: "conformance-request",
            Operation: "conformance",
            DeviceIdentity: "test-device",
            Nonce: "test-nonce",
            ExpiresAt: DateTimeOffset.UtcNow.AddMinutes(5),
            PolicyVersion: "conformance-v1",
            AuthorizationState: "test-only");

    private static IEnumerable<(ITrustProvider Provider, string Id, string DisabledCode)>
        Providers()
    {
        yield return (
            new WindowsTpmProvider(),
            "windows-tpm2",
            "TPM_OPERATION_DISABLED");

        yield return (
            new LinuxTpmProvider(),
            "linux-tpm2",
            "TPM_OPERATION_DISABLED");

        yield return (
            new MacOsSecureEnclaveProvider(),
            "macos-secure-enclave",
            "SECURE_ENCLAVE_OPERATION_DISABLED");

        yield return (
            new AndroidKeystoreProvider(),
            "android-keystore",
            "ANDROID_KEYSTORE_OPERATION_DISABLED");

        yield return (
            new IosSecureEnclaveProvider(),
            "ios-secure-enclave",
            "IOS_SECURE_ENCLAVE_OPERATION_DISABLED");
    }

    [TestMethod]
    public void Providers_Have_Stable_Unique_Identifiers()
    {
        var providers = Providers().ToArray();

        CollectionAssert.AllItemsAreUnique(
            providers.Select(x => x.Provider.ProviderId).ToArray());

        foreach (var entry in providers)
        {
            Assert.AreEqual(entry.Id, entry.Provider.ProviderId);
            Assert.IsFalse(string.IsNullOrWhiteSpace(entry.Provider.ProviderId));
        }
    }

    [TestMethod]
    public void Providers_Advertise_Expected_Contract_Capabilities()
    {
        foreach (var entry in Providers())
        {
            Assert.AreEqual(
                ExpectedCapabilities,
                entry.Provider.GetCapabilities(),
                $"Capability mismatch: {entry.Provider.ProviderId}");
        }
    }

    [TestMethod]
    public async Task Enrollment_Is_Fail_Closed_For_All_Providers()
    {
        foreach (var entry in Providers())
        {
            var result = await entry.Provider.EnrollAsync(
                Request(),
                CancellationToken.None);

            Assert.IsFalse(result.Success, entry.Provider.ProviderId);
            Assert.IsNull(result.PublicIdentity, entry.Provider.ProviderId);
            Assert.AreEqual(
                entry.DisabledCode,
                result.ErrorCode,
                entry.Provider.ProviderId);
        }
    }

    [TestMethod]
    public async Task Authorization_Is_Fail_Closed_For_All_Providers()
    {
        foreach (var entry in Providers())
        {
            var result = await entry.Provider.AuthorizeAsync(
                Request(),
                CancellationToken.None);

            AssertOperationDisabled(entry, result);
        }
    }

    [TestMethod]
    public async Task Attestation_Is_Fail_Closed_For_All_Providers()
    {
        foreach (var entry in Providers())
        {
            var result = await entry.Provider.AttestAsync(
                Request(),
                CancellationToken.None);

            AssertOperationDisabled(entry, result);
        }
    }

    [TestMethod]
    public async Task Signing_Is_Fail_Closed_For_All_Providers()
    {
        ReadOnlyMemory<byte> data =
            new byte[] { 0x43, 0x4F, 0x4E, 0x44, 0x4F, 0x52 };

        foreach (var entry in Providers())
        {
            var result = await entry.Provider.SignAsync(
                Request(),
                data,
                CancellationToken.None);

            AssertOperationDisabled(entry, result);
        }
    }

    [TestMethod]
    public async Task Revocation_Is_Fail_Closed_For_All_Providers()
    {
        foreach (var entry in Providers())
        {
            var result = await entry.Provider.RevokeAsync(
                Request(),
                CancellationToken.None);

            AssertOperationDisabled(entry, result);
        }
    }

    private static void AssertOperationDisabled(
        (ITrustProvider Provider, string Id, string DisabledCode) entry,
        TrustOperationResult result)
    {
        Assert.IsFalse(result.Success, entry.Provider.ProviderId);

        Assert.AreEqual(
            entry.DisabledCode,
            result.ResultCode,
            entry.Provider.ProviderId);

        Assert.IsNull(
            result.PublicResult,
            entry.Provider.ProviderId);
    }
}
