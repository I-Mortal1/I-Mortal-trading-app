namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Independently establishes that the required VeraCrypt USB custody source
/// is unavailable before email recovery may be considered.
///
/// Caller assertion is insufficient.
///
/// This interface grants no authority.
/// </summary>
public interface IDeveloperUsbUnavailabilityVerifier
{
    bool IsUnavailable(
        VeraCryptUsbKeyCustodyDescriptor requiredCustody);
}