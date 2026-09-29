using IMortal.TrustBroker.Mobile;
using IMortal.TrustBroker.Mobile.Android;
using IMortal.TrustBroker.Mobile.IOS;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class MobileEvidenceConformanceTests
{
    // ------------------------------------------------------------
    // Android evidence mapping
    // ------------------------------------------------------------

    [TestMethod]
    public void Android_Unknown_Is_Not_Hardware_Backed()
    {
        var native = new AndroidNativeProbeResult(
            PlatformAvailable: true,
            HardwareEvidence: AndroidHardwareSecurityEvidence.Unknown,
            HardwareReady: true);

        var result = AndroidNativeProbeConverter.Convert(native);

        Assert.AreEqual(
            MobileHardwareSecurityLevel.Unknown,
            result.SecurityLevel);

        Assert.IsFalse(result.HardwareBacked);
        Assert.IsFalse(result.HardwareReady);
        Assert.IsTrue(AndroidProbeInvariants.Validate(native));
    }

    [TestMethod]
    public void Android_SoftwareOnly_Is_Not_Hardware_Backed()
    {
        var native = new AndroidNativeProbeResult(
            PlatformAvailable: true,
            HardwareEvidence: AndroidHardwareSecurityEvidence.SoftwareOnly,
            HardwareReady: true);

        var result = AndroidNativeProbeConverter.Convert(native);

        Assert.AreEqual(
            MobileHardwareSecurityLevel.Software,
            result.SecurityLevel);

        Assert.IsFalse(result.HardwareBacked);
        Assert.IsFalse(result.HardwareReady);
        Assert.IsTrue(AndroidProbeInvariants.Validate(native));
    }

    [TestMethod]
    public void Android_Tee_Is_Hardware_Backed()
    {
        var native = new AndroidNativeProbeResult(
            PlatformAvailable: true,
            HardwareEvidence:
                AndroidHardwareSecurityEvidence.TrustedExecutionEnvironment,
            HardwareReady: true);

        var result = AndroidNativeProbeConverter.Convert(native);

        Assert.AreEqual(
            MobileHardwareSecurityLevel.Tee,
            result.SecurityLevel);

        Assert.IsTrue(result.HardwareBacked);
        Assert.IsTrue(result.HardwareReady);
        Assert.IsTrue(AndroidProbeInvariants.Validate(native));
    }

    [TestMethod]
    public void Android_StrongBox_Is_Hardware_Backed()
    {
        var native = new AndroidNativeProbeResult(
            PlatformAvailable: true,
            HardwareEvidence: AndroidHardwareSecurityEvidence.StrongBox,
            HardwareReady: true);

        var result = AndroidNativeProbeConverter.Convert(native);

        Assert.AreEqual(
            MobileHardwareSecurityLevel.StrongBox,
            result.SecurityLevel);

        Assert.IsTrue(result.HardwareBacked);
        Assert.IsTrue(result.HardwareReady);
        Assert.IsTrue(AndroidProbeInvariants.Validate(native));
    }

    [TestMethod]
    public void Android_Platform_Unavailable_Cannot_Be_Hardware_Ready()
    {
        var native = new AndroidNativeProbeResult(
            PlatformAvailable: false,
            HardwareEvidence: AndroidHardwareSecurityEvidence.StrongBox,
            HardwareReady: true);

        var result = AndroidNativeProbeConverter.Convert(native);

        Assert.IsTrue(result.HardwareBacked);
        Assert.IsFalse(result.HardwareReady);
        Assert.IsTrue(AndroidProbeInvariants.Validate(native));
    }

    // ------------------------------------------------------------
    // iOS evidence mapping
    // ------------------------------------------------------------

    [TestMethod]
    public void Ios_Unknown_Is_Not_Hardware_Backed()
    {
        var native = new IosNativeProbeResult(
            PlatformAvailable: true,
            HardwareEvidence: IosHardwareSecurityEvidence.Unknown,
            HardwareReady: true);

        var result = IosNativeProbeConverter.Convert(native);

        Assert.AreEqual(
            MobileHardwareSecurityLevel.Unknown,
            result.SecurityLevel);

        Assert.IsFalse(result.HardwareBacked);
        Assert.IsFalse(result.HardwareReady);
        Assert.IsTrue(IosProbeInvariants.Validate(native));
    }

    [TestMethod]
    public void Ios_SoftwareOnly_Is_Not_Hardware_Backed()
    {
        var native = new IosNativeProbeResult(
            PlatformAvailable: true,
            HardwareEvidence: IosHardwareSecurityEvidence.SoftwareOnly,
            HardwareReady: true);

        var result = IosNativeProbeConverter.Convert(native);

        Assert.AreEqual(
            MobileHardwareSecurityLevel.Software,
            result.SecurityLevel);

        Assert.IsFalse(result.HardwareBacked);
        Assert.IsFalse(result.HardwareReady);
        Assert.IsTrue(IosProbeInvariants.Validate(native));
    }

    [TestMethod]
    public void Ios_SecureEnclave_Is_Hardware_Backed()
    {
        var native = new IosNativeProbeResult(
            PlatformAvailable: true,
            HardwareEvidence: IosHardwareSecurityEvidence.SecureEnclave,
            HardwareReady: true);

        var result = IosNativeProbeConverter.Convert(native);

        Assert.AreEqual(
            MobileHardwareSecurityLevel.SecureEnclave,
            result.SecurityLevel);

        Assert.IsTrue(result.HardwareBacked);
        Assert.IsTrue(result.HardwareReady);
        Assert.IsTrue(IosProbeInvariants.Validate(native));
    }

    [TestMethod]
    public void Ios_Platform_Unavailable_Cannot_Be_Hardware_Ready()
    {
        var native = new IosNativeProbeResult(
            PlatformAvailable: false,
            HardwareEvidence: IosHardwareSecurityEvidence.SecureEnclave,
            HardwareReady: true);

        var result = IosNativeProbeConverter.Convert(native);

        Assert.IsTrue(result.HardwareBacked);
        Assert.IsFalse(result.HardwareReady);
        Assert.IsTrue(IosProbeInvariants.Validate(native));
    }
}

