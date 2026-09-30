namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Stateless prerequisite verification through the existing trusted boundary.
/// Root transaction ownership is checked by the root before invoking this gate.
/// No result is cached and no parameterless or exceptional path approves.
/// </summary>
public sealed class TransactionBoundApprovedWorkloadGate : IApprovedWorkloadGate
{
    private readonly IApprovedWorkloadTrustedEvidenceBoundary _trustedEvidenceBoundary;

    public TransactionBoundApprovedWorkloadGate(
        IApprovedWorkloadTrustedEvidenceBoundary trustedEvidenceBoundary)
    {
        _trustedEvidenceBoundary = trustedEvidenceBoundary ??
            throw new ArgumentNullException(nameof(trustedEvidenceBoundary));
    }

    public bool IsApproved() => false;

    public bool IsApproved(ApprovedWorkloadEvaluationContext context)
    {
        try
        {
            return context is not null &&
                _trustedEvidenceBoundary.Verify(
                    context.Evidence, context.RequiredPolicy,
                    context.Challenge, context.EvaluationTime);
        }
        catch
        {
            return false;
        }
    }
}
