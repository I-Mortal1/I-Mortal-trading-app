namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IRecoveryIntegrityEvidenceProducer :
    ITypedVerificationEvidenceProducer
{
    RecoveryIntegrityEvidence Produce(
        ProtectedStateRecoveryRecord recoveryRecord,
        RecoveryRecordIntegrityVerification verification,
        VerificationEvidenceBinding binding);
}
