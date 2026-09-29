namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Safe placeholder until the real approved-workload verifier is composed.
/// </summary>
public sealed class DenyAllApprovedWorkloadGate :
    IApprovedWorkloadGate
{
    public bool IsApproved() => false;
}