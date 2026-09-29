namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IProtectedStateRecoveryConformance
{
    ProtectedStateRecoveryDisposition Evaluate(
        ProtectedStateRecoveryRecord recoveryRecord,
        RecoveryRecordIntegrityVerification integrityVerification,
        ProtectedStateCommitMarker? commitMarker,
        DurabilityProof? durabilityProof,
        ConfidentialSecurityBoundaryIdentity boundaryIdentity);
}
