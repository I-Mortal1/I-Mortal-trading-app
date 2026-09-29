namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IConfidentialComputeAttestationVerifier
{
    bool Verify(IConfidentialComputeEvidence evidence);
}
