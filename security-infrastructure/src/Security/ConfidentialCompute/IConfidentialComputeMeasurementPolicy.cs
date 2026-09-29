namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IConfidentialComputeMeasurementPolicy
{
    bool Accept(IConfidentialComputeEvidence evidence);
}
