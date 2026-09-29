namespace IMortal.TrustBroker.Mobile;

public enum MobileHardwareSecurityLevel
{
    Unknown = 0,
    Software = 1,
    Tee = 2,
    StrongBox = 3,
    SecureEnclave = 4
}

public sealed record MobileTrustProbeResult(
    bool PlatformAvailable,
    bool HardwareBacked,
    bool HardwareReady,
    MobileHardwareSecurityLevel SecurityLevel);
