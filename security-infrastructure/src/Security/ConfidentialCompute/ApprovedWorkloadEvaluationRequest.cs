namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Fresh root-owned evaluation identity and its single captured instant.
/// It grants no authority and does not issue an attestation challenge.
/// A producer must independently establish input provenance before using it.
/// </summary>
public sealed class ApprovedWorkloadEvaluationRequest
{
    internal ApprovedWorkloadEvaluationRequest(DateTimeOffset evaluationTime)
    {
        if (evaluationTime == default)
            throw new ArgumentOutOfRangeException(nameof(evaluationTime));
        EvaluationTime = evaluationTime;
    }

    internal ApprovedWorkloadEvaluationRequest(IssuedAuthorization issued)
        : this(issued.Owner.EvaluationTime) { Issued = issued; }

    /// <summary>Exact shared issuance; absent on legacy standalone requests.</summary>
    public IssuedAuthorization? Issued { get; }

    public DateTimeOffset EvaluationTime { get; }

    /// <summary>
    /// Bind inputs to this request. This performs no authentication and cannot
    /// turn caller-controlled policy or untrusted evidence into trusted inputs.
    /// </summary>
    public ApprovedWorkloadEvaluationContext CreateContext(
        ProjectIntegrityEvidence evidence,
        ProjectIntegrityPolicy requiredPolicy,
        AttestationChallenge challenge) =>
        new(this, evidence, requiredPolicy, challenge);
}
