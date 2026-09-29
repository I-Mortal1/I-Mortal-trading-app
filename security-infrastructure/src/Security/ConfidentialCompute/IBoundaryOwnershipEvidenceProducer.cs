namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IBoundaryOwnershipEvidenceProducer :
    ITypedVerificationEvidenceProducer
{
    BoundaryOwnershipEvidence Produce(
        ConfidentialSecurityBoundaryIdentity expectedBoundary,
        ConfidentialSecurityBoundaryIdentity verifiedBoundary,
        VerificationEvidenceBinding binding);
}
