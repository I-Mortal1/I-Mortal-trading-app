namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface ITrustedProducerProvenanceVerifier
{
    bool Verify(
        TrustedProducerProvenance provenance,
        ConfidentialSecurityBoundaryIdentity expectedBoundaryIdentity,
        long expectedProtectedStateVersion,
        byte[] expectedProtectedStateDigest);
}
