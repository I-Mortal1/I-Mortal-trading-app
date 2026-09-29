namespace IMortal.TrustBroker.Mobile.IOS;

public sealed record IosNativeProbeResult(
    bool PlatformAvailable,
    IosHardwareSecurityEvidence HardwareEvidence,
    bool HardwareReady);
