namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public enum RootConfidentialComputeDenialReason
{
    None = 0,
    Unverified,
    NoEvidence,
    UnknownEvidenceOrigin,
    TestEvidenceInProduction,
    UnsupportedPlatform,
    TeeBoundaryMissing,
    AttestationMissing,
    AttestationInvalid,
    AttestationStale,
    MeasurementInvalid,
    WorkloadBindingInvalid,
    PlatformBindingInvalid,
    PolicyBindingInvalid,
    SignedArtifactInvalid,
    EvidenceProviderFailure,
    VerifierFailure,
    PolicyFailure,
    EvidenceRevoked
}
