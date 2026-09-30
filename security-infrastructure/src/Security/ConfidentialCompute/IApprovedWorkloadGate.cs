namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Independent approved-workload decision boundary.
///
/// Implementations must establish workload identity from trusted evidence.
/// Caller-asserted approval is not accepted by this interface.
/// </summary>
public interface IApprovedWorkloadGate
{
    bool IsApproved();

    /// <summary>
    /// Evaluate the exact context supplied by the owning root transaction.
    /// Legacy implementations deny until they explicitly implement this path.
    /// The parameterless method must never be used as a fallback.
    /// </summary>
    bool IsApproved(ApprovedWorkloadEvaluationContext context) => false;
}