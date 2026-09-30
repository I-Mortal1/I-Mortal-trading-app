namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Trusted composition dependency, not a caller input or provenance proof.
/// An implementation must independently authenticate acquisition, required
/// policy and challenge ownership for this request. Missing provenance denies.
/// It must return a context created through this exact request, never reuse a
/// context or approval from another request, and preserve challenge replay rules.
/// No approving production implementation is supplied by this change.
/// </summary>
public interface IApprovedWorkloadContextProducer
{
    bool TryProduce(
        ApprovedWorkloadEvaluationRequest request,
        out ApprovedWorkloadEvaluationContext? context);
}
