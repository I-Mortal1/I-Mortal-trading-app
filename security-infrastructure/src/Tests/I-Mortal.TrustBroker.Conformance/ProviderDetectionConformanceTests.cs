using IMortal.TrustBroker.Providers;
using IMortal.TrustBroker.Providers.Android;
using IMortal.TrustBroker.Providers.IOS;
using IMortal.TrustBroker.Providers.Linux;
using IMortal.TrustBroker.Providers.MacOS;
using IMortal.TrustBroker.Providers.Windows;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class ProviderDetectionConformanceTests
{
    [TestMethod]
    public void Factory_Selects_Windows_Tpm_Provider_On_Windows_Build()
    {
        Assert.IsTrue(OperatingSystem.IsWindows());

        var provider = TrustProviderFactory.Create();

        Assert.IsInstanceOfType<WindowsTpmProvider>(provider);
        Assert.AreEqual("windows-tpm2", provider.ProviderId);
    }

    [TestMethod]
    public void Non_Windows_Providers_Fail_Closed_On_Windows()
    {
        Assert.IsTrue(OperatingSystem.IsWindows());

        ITrustProvider[] providers =
        [
            new LinuxTpmProvider(),
            new MacOsSecureEnclaveProvider(),
            new AndroidKeystoreProvider(),
            new IosSecureEnclaveProvider()
        ];

        foreach (var provider in providers)
        {
            var detection = provider.Detect();

            Assert.AreEqual(
                TrustProviderState.Unavailable,
                detection.State,
                provider.ProviderId);

            Assert.AreEqual(
                provider.ProviderId,
                detection.ProviderId,
                provider.ProviderId);

            Assert.IsFalse(
                detection.HardwareBacked,
                provider.ProviderId);

            Assert.IsFalse(
                detection.NonExportableKeysSupported,
                provider.ProviderId);

            Assert.IsFalse(
                provider.IsAvailable(),
                provider.ProviderId);
        }
    }

    [TestMethod]
    public void Windows_Detection_Identity_Is_Internally_Consistent()
    {
        Assert.IsTrue(OperatingSystem.IsWindows());

        var provider = new WindowsTpmProvider();
        var detection = provider.Detect();

        Assert.AreEqual(
            provider.ProviderId,
            detection.ProviderId);

        Assert.AreEqual(
            "windows-tpm2",
            detection.ProviderId);

        if (detection.State == TrustProviderState.Unavailable)
        {
            Assert.IsFalse(detection.HardwareBacked);
            Assert.IsFalse(detection.NonExportableKeysSupported);
        }
        else
        {
            Assert.IsTrue(
                detection.State is
                    TrustProviderState.HardwareDetected or
                    TrustProviderState.HardwareReady);

            Assert.IsTrue(detection.HardwareBacked);
            Assert.IsTrue(detection.NonExportableKeysSupported);
        }
    }

    [TestMethod]
    public void Windows_IsAvailable_Agrees_With_Detection_State()
    {
        Assert.IsTrue(OperatingSystem.IsWindows());

        var provider = new WindowsTpmProvider();

        var detection = provider.Detect();
        var available = provider.IsAvailable();

        Assert.AreEqual(
            detection.State != TrustProviderState.Unavailable,
            available);
    }

    [TestMethod]
    public void Detection_Cannot_Claim_Authorization_State()
    {
        Assert.IsTrue(OperatingSystem.IsWindows());

        var provider = new WindowsTpmProvider();
        var detection = provider.Detect();

        Assert.IsLessThan(
            (int)TrustProviderState.IdentityEnrolled,
            (int)detection.State,
            $"Detection unexpectedly crossed authorization boundary: {detection.State}");
    }
}


