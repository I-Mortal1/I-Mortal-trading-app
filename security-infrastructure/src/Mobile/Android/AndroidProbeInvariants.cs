namespace IMortal.TrustBroker.Mobile.Android;

public static class AndroidProbeInvariants
{
    public static bool Validate(AndroidNativeProbeResult native)
    {
        var result = AndroidNativeProbeConverter.Convert(native);

        if (!native.PlatformAvailable && result.HardwareReady)
            return false;

        if (!result.HardwareBacked && result.HardwareReady)
            return false;

        if (native.HardwareEvidence is
            AndroidHardwareSecurityEvidence.Unknown or
            AndroidHardwareSecurityEvidence.SoftwareOnly)
        {
            if (result.HardwareBacked || result.HardwareReady)
                return false;
        }

        return true;
    }
}
