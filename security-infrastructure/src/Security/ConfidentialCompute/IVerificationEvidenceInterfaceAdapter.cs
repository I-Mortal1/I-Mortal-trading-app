namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Adapts already-produced typed verification evidence into the
/// existing verification domain without manufacturing, upgrading,
/// or synthesizing trust.
///
/// An implementation must fail closed when evidence provenance,
/// binding, digest, boundary identity, or evidence version cannot
/// be established.
/// </summary>
public interface IVerificationEvidenceInterfaceAdapter
{
    RecoveryRecordIntegrityVerification AdaptRecoveryIntegrity(
        RecoveryIntegrityEvidence evidence);

    DurabilityProof AdaptDurability(
        DurabilityEvidence evidence);

    ConfidentialSecurityBoundaryIdentity AdaptBoundaryOwnership(
        BoundaryOwnershipEvidence evidence);

    ProtectedStateCommitMarker AdaptCommitMarker(
        CommitMarkerEvidence evidence);
}
