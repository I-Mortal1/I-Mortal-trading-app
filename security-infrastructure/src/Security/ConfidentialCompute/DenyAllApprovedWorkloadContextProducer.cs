namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>Missing trusted producer provisioning always denies.</summary>
public sealed class DenyAllApprovedWorkloadContextProducer : IApprovedWorkloadContextProducer
{
    public bool TryProduce(
        ApprovedWorkloadEvaluationRequest request,
        out ApprovedWorkloadEvaluationContext? context)
    {
        context = null;
        return false;
    }
}
