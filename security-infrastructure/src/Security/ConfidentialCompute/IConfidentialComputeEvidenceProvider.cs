namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IConfidentialComputeEvidenceProvider
{
    IConfidentialComputeEvidence? Collect();
}
