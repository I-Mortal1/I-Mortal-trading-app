using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable transaction-bound inputs for one approved-workload
/// trusted-evidence evaluation.
///
/// SECURITY BOUNDARY:
///
/// This object is not authorization.
///
/// It carries the exact authoritative evidence, policy, challenge, and
/// trusted evaluation instant belonging to one evaluation.
///
/// EvaluationTime must eventually be captured from ISecurityClock exactly
/// once by the owning transaction/root boundary.
///
/// This type does not read a clock itself.
///
/// It contains no global approval state, no cached success, no ambient
/// authorization, and no reusable authorization token.
///
/// Possession of this object grants no source mutation, production,
/// signing, TEE, attestation, workload execution, user-runtime,
/// developer-source, or I-Mortal Security Umbrella root authority.
/// </summary>
public sealed class ApprovedWorkloadEvaluationContext
{
    public ApprovedWorkloadEvaluationContext(
        ProjectIntegrityEvidence evidence,
        ProjectIntegrityPolicy requiredPolicy,
        AttestationChallenge challenge,
        DateTimeOffset evaluationTime)
    {
        Evidence =
            evidence ??
            throw new ArgumentNullException(nameof(evidence));

        RequiredPolicy =
            requiredPolicy ??
            throw new ArgumentNullException(nameof(requiredPolicy));

        Challenge =
            challenge ??
            throw new ArgumentNullException(nameof(challenge));

        if (evaluationTime == default)
        {
            throw new ArgumentOutOfRangeException(
                nameof(evaluationTime));
        }

        EvaluationTime = evaluationTime;
    }

    public ProjectIntegrityEvidence Evidence { get; }

    public ProjectIntegrityPolicy RequiredPolicy { get; }

    public AttestationChallenge Challenge { get; }

    public DateTimeOffset EvaluationTime { get; }
}