namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IAttestedVerifierProvenanceVerifier
{
    bool Verify(
        AttestedVerifierProvenance provenance,
        ConfidentialPlatformClass expectedPlatform,
        AttestationChallenge expectedChallenge,
        string expectedEvidenceDigest);
}