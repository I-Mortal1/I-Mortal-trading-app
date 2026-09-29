using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Fail-closed strict AND-only project-integrity composition.
///
/// Authorization is never inferred from either verifier independently.
///
/// BOTH:
///
/// 1. IProjectIntegrityVerifier
/// 2. IProjectIntegrityChallengeBindingVerifier
///
/// must independently return true for the same evidence and evaluation.
///
/// No OR path exists.
/// No fallback path exists.
/// No exception path authorizes.
/// No partial success authorizes.
///
/// Returning true remains project-integrity evidence only and does not
/// independently grant source-mutation or any other authority.
/// </summary>
public sealed class CompositeProjectIntegrityGate :
    ICompositeProjectIntegrityGate
{
    private readonly IProjectIntegrityVerifier _integrityVerifier;

    private readonly IProjectIntegrityChallengeBindingVerifier
        _challengeBindingVerifier;

    public CompositeProjectIntegrityGate(
        IProjectIntegrityVerifier integrityVerifier,
        IProjectIntegrityChallengeBindingVerifier challengeBindingVerifier)
    {
        _integrityVerifier =
            integrityVerifier ??
            throw new ArgumentNullException(
                nameof(integrityVerifier));

        _challengeBindingVerifier =
            challengeBindingVerifier ??
            throw new ArgumentNullException(
                nameof(challengeBindingVerifier));
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

            // Strict sequential AND.
            //
            // Do not collapse this into caller-supplied status values.
            // Each verifier independently evaluates the authoritative
            // inputs supplied to this composition.

            bool integrityAccepted =
                _integrityVerifier.Verify(
                    evidence,
                    requiredPolicy,
                    now);

            if (!integrityAccepted)
            {
                return false;
            }

            bool challengeBindingAccepted =
                _challengeBindingVerifier.Verify(
                    evidence,
                    challenge,
                    now);

            if (!challengeBindingAccepted)
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