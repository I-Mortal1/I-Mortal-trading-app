namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IDurabilityEvidenceProducer :
    ITypedVerificationEvidenceProducer
{
    DurabilityEvidence Produce(
        ProtectedStateRecoveryRecord recoveryRecord,
        ProtectedStateCommitMarker commitMarker,
        DurabilityProof durabilityProof,
        VerificationEvidenceBinding binding);
}
