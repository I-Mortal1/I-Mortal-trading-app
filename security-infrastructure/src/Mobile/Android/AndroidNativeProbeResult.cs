namespace IMortal.TrustBroker.Mobile.Android;

public sealed record AndroidNativeProbeResult(
    bool PlatformAvailable,
    AndroidHardwareSecurityEvidence HardwareEvidence,
    bool HardwareReady);
