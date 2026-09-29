using IMortal.TrustBroker.Mobile;

namespace IMortal.TrustBroker.Mobile.Android;

public static class AndroidHardwareEvidenceMapper
{
    public static MobileHardwareSecurityLevel Map(
        AndroidHardwareSecurityEvidence evidence) =>
        evidence switch
        {
            AndroidHardwareSecurityEvidence.TrustedExecutionEnvironment
                => MobileHardwareSecurityLevel.Tee,

            AndroidHardwareSecurityEvidence.StrongBox
                => MobileHardwareSecurityLevel.StrongBox,

            AndroidHardwareSecurityEvidence.SoftwareOnly
                => MobileHardwareSecurityLevel.Software,

            _ => MobileHardwareSecurityLevel.Unknown
        };

    public static bool IsHardwareBacked(
        AndroidHardwareSecurityEvidence evidence) =>
        evidence is
            AndroidHardwareSecurityEvidence.TrustedExecutionEnvironment or
            AndroidHardwareSecurityEvidence.StrongBox;
}
