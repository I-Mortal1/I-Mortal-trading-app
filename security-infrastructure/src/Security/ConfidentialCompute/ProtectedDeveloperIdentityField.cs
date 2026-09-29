namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Identifies an independently protected field within the canonical
/// developer identity.
///
/// This enum is classification metadata only.
/// It grants no authority.
/// </summary>
public enum ProtectedDeveloperIdentityField
{
    None = 0,

    CompleteUsbIdentity = 1,

    UsbIdNumber = 2,

    RecoveryEmail = 3
}