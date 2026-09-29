namespace IMortal.TrustBroker.Mobile.IOS;

public static class IosProbeInvariants
{
    public static bool Validate(IosNativeProbeResult native)
    {
        var result = IosNativeProbeConverter.Convert(native);

        if (!native.PlatformAvailable && result.HardwareReady)
            return false;

        if (!result.HardwareBacked && result.HardwareReady)
            return false;

        if (native.HardwareEvidence is
            IosHardwareSecurityEvidence.Unknown or
            IosHardwareSecurityEvidence.SoftwareOnly)
        {
            if (result.HardwareBacked || result.HardwareReady)
                return false;
        }

        return true;
    }
}
