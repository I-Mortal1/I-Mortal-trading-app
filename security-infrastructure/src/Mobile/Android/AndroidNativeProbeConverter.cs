using IMortal.TrustBroker.Mobile;

namespace IMortal.TrustBroker.Mobile.Android;

public static class AndroidNativeProbeConverter
{
    public static MobileTrustProbeResult Convert(
        AndroidNativeProbeResult native)
    {
        var level =
            AndroidHardwareEvidenceMapper.Map(native.HardwareEvidence);

        var hardwareBacked =
            AndroidHardwareEvidenceMapper.IsHardwareBacked(
                native.HardwareEvidence);

        var hardwareReady =
            native.PlatformAvailable &&
            hardwareBacked &&
            native.HardwareReady;

        return new MobileTrustProbeResult(
            native.PlatformAvailable,
            hardwareBacked,
            hardwareReady,
            level);
    }
}
