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
}