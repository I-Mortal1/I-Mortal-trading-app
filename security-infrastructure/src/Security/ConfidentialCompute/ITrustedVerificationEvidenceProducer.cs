namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface ITrustedVerificationEvidenceProducer
{
    RecoveryIntegrityEvidence ProduceRecoveryIntegrityEvidence(
        TrustedProducerContext context,
        ProtectedStateRecoveryRecord recoveryRecord);

    DurabilityEvidence ProduceDurabilityEvidence(
        TrustedProducerContext context,
        ProtectedStateRecoveryRecord recoveryRecord,
        ProtectedStateCommitMarker commitMarker);

    BoundaryOwnershipEvidence ProduceBoundaryOwnershipEvidence(
        TrustedProducerContext context,
        TrustedProducerProvenance provenance);

    CommitMarkerEvidence ProduceCommitMarkerEvidence(
        TrustedProducerContext context,
        ProtectedStateCommitMarker commitMarker);
}