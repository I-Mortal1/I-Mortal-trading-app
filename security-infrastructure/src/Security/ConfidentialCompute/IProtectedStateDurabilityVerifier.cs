namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IProtectedStateDurabilityVerifier
{
    DurabilityProof VerifyDurability(
        ProtectedStateRecoveryRecord recoveryRecord,
        ProtectedStateCommitMarker commitMarker,
        ConfidentialSecurityBoundaryIdentity boundaryIdentity);
}
