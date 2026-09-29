namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IRecoveryRecordIntegrityVerifier
{
    RecoveryRecordIntegrityVerification Verify(
        ProtectedStateRecoveryRecord recoveryRecord,
        ConfidentialSecurityBoundaryIdentity boundaryIdentity);
}
