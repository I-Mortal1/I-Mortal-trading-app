using IMortal.TrustBroker.Mobile;

namespace IMortal.TrustBroker.Mobile.IOS;

public static class IosNativeProbeConverter
{
    public static MobileTrustProbeResult Convert(
        IosNativeProbeResult native)
    {
        var level =
            IosHardwareEvidenceMapper.Map(native.HardwareEvidence);

        var hardwareBacked =
            IosHardwareEvidenceMapper.IsHardwareBacked(
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
