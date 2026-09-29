using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Fail-closed approved-workload trusted-evidence boundary.
///
/// This implementation deliberately reuses the authoritative
/// ICompositeProjectIntegrityGate.
///
/// It does not create a second workload identity, workload digest,
/// challenge verifier, project-integrity verifier, or authorization path.
///
/// The approved workload digest remains part of the exact
/// ProjectIntegrityEvidence / ProjectIntegrityPolicy relationship already
/// verified by the project-integrity composition.
///
/// No caller-provided boolean approval is accepted.
/// No fallback path exists.
/// No exception authorizes.
/// No partial verification authorizes.
///
/// Returning true remains prerequisite evidence only.
/// </summary>
public sealed class ApprovedWorkloadTrustedEvidenceBoundary :
    IApprovedWorkloadTrustedEvidenceBoundary
{
    private readonly ICompositeProjectIntegrityGate
        _projectIntegrityGate;

    public ApprovedWorkloadTrustedEvidenceBoundary(
        ICompositeProjectIntegrityGate projectIntegrityGate)
    {
        _projectIntegrityGate =
            projectIntegrityGate ??
            throw new ArgumentNullException(
                nameof(projectIntegrityGate));
    }

    public bool Verify(
        ProjectIntegrityEvidence evidence,
        ProjectIntegrityPolicy requiredPolicy,
        AttestationChallenge challenge,
        DateTimeOffset now)
    {
        try
        {
            if (evidence is null ||
                requiredPolicy is null ||
                challenge is null ||
                now == default)
            {
                return false;
            }

            // Strict delegation to the authoritative project-integrity
            // composition.
            //
            // That composition independently requires BOTH:
            //
            // 1. project-integrity verification, including the exact
            //    approved-workload digest required by immutable policy;
            //
            // 2. exact cryptographic challenge binding.
            //
            // This boundary does not manufacture or infer either result.

            bool trustedEvidenceAccepted =
                _projectIntegrityGate.Verify(
                    evidence,
                    requiredPolicy,
                    challenge,
                    now);

            if (!trustedEvidenceAccepted)
            {
                return false;
            }

            return true;
        }
        catch
        {
            // Security boundary:
            // every unexpected condition is denial.
            return false;
        }
    }
}