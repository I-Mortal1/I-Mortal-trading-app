namespace IMortal.TrustBroker.Security.ConfidentialCompute;

internal sealed class ConfidentialRecoveryDurabilityOwnershipConformance
{
    public bool Verify(
        bool recoveryIntegrityVerified,
        bool durabilityVerified,
        bool recoveryOwnershipVerified,
        bool durabilityOwnershipVerified,
        bool commitMarkerOwnershipVerified)
    {
        return
            recoveryIntegrityVerified &&
            durabilityVerified &&
            recoveryOwnershipVerified &&
            durabilityOwnershipVerified &&
            commitMarkerOwnershipVerified;
    }
}
