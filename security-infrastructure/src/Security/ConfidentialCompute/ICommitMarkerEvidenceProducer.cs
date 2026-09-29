namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface ICommitMarkerEvidenceProducer :
    ITypedVerificationEvidenceProducer
{
    CommitMarkerEvidence Produce(
        ProtectedStateCommitMarker commitMarker,
        DurabilityProof durabilityProof,
        VerificationEvidenceBinding binding);
}
