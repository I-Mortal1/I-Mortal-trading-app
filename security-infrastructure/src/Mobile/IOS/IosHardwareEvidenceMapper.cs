using IMortal.TrustBroker.Mobile;

namespace IMortal.TrustBroker.Mobile.IOS;

public static class IosHardwareEvidenceMapper
{
    public static MobileHardwareSecurityLevel Map(
        IosHardwareSecurityEvidence evidence) =>
        evidence switch
        {
            IosHardwareSecurityEvidence.SecureEnclave
                => MobileHardwareSecurityLevel.SecureEnclave,

            IosHardwareSecurityEvidence.SoftwareOnly
                => MobileHardwareSecurityLevel.Software,

            _ => MobileHardwareSecurityLevel.Unknown
        };

    public static bool IsHardwareBacked(
        IosHardwareSecurityEvidence evidence) =>
        evidence == IosHardwareSecurityEvidence.SecureEnclave;
}
