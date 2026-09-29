using System;
using System.Security.Cryptography;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Concrete fail-closed implementation of IProjectIntegrityVerifier.
///
/// This verifier establishes:
///
/// - exact project identity,
/// - exact manifest identity,
/// - exact project-manifest digest,
/// - exact protected-source-tree digest,
/// - exact approved-workload digest,
/// - evidence timestamp validity and freshness,
/// - presence of a challenge binding.
///
/// IMPORTANT:
///
/// The current R9 verifier interface does not receive the originating
/// challenge. Therefore this implementation cannot independently recompute
/// the challenge binding.
///
/// Presence of ChallengeBinding is required here, but independent challenge
/// verification MUST occur in the surrounding authorization composition
/// before this verifier can participate in any source-mutation decision.
///
/// Returning true from this verifier is integrity evidence only.
///
/// It does not independently grant source mutation, signing, production,
/// workload execution, trading, provider-dispatch, user-runtime, developer
/// source, or I-Mortal Security Umbrella root authority.
/// </summary>
public sealed class ProjectIntegrityVerifier : IProjectIntegrityVerifier
{
    private static readonly TimeSpan MaximumEvidenceAge =
        TimeSpan.FromMinutes(5);

    private static readonly TimeSpan MaximumFutureClockSkew =
        TimeSpan.FromMinutes(1);

    public bool Verify(
        ProjectIntegrityEvidence evidence,
        ProjectIntegrityPolicy requiredPolicy,
        DateTimeOffset now)
    {
        try
        {
            if (evidence is null)
            {
                return false;
            }

            if (requiredPolicy is null)
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    evidence.ProjectIdentity))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    requiredPolicy.ProjectIdentity))
            {
                return false;
            }

            if (!string.Equals(
                    evidence.ProjectIdentity,
                    requiredPolicy.ProjectIdentity,
                    StringComparison.Ordinal))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    evidence.ManifestIdentity))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(
                    requiredPolicy.ManifestIdentity))
            {
                return false;
            }

            if (!string.Equals(
                    evidence.ManifestIdentity,
                    requiredPolicy.ManifestIdentity,
                    StringComparison.Ordinal))
            {
                return false;
            }

            if (!IsFresh(
                    evidence.ObservedAt,
                    now))
            {
                return false;
            }

            byte[] challengeBinding =
                evidence.ChallengeBinding;

            if (challengeBinding is null ||
                challengeBinding.Length == 0)
            {
                return false;
            }

            if (!FixedTimeEqualsRequired(
                    evidence.ProjectManifestDigest,
                    requiredPolicy.RequiredProjectManifestDigest))
            {
                return false;
            }

            if (!FixedTimeEqualsRequired(
                    evidence.SourceTreeDigest,
                    requiredPolicy.RequiredSourceTreeDigest))
            {
                return false;
            }

            if (!FixedTimeEqualsRequired(
                    evidence.ApprovedWorkloadDigest,
                    requiredPolicy.RequiredApprovedWorkloadDigest))
            {
                return false;
            }

            return true;
        }
        catch
        {
            // Security boundary:
            // unexpected conditions are denial, never authorization.
            return false;
        }
    }

    private static bool IsFresh(
        DateTimeOffset observedAt,
        DateTimeOffset now)
    {
        if (observedAt == default ||
            now == default)
        {
            return false;
        }

        if (observedAt > now)
        {
            TimeSpan futureOffset =
                observedAt - now;

            if (futureOffset > MaximumFutureClockSkew)
            {
                return false;
            }
        }

        TimeSpan age =
            now - observedAt;

        if (age < TimeSpan.Zero)
        {
            age = TimeSpan.Zero;
        }

        if (age > MaximumEvidenceAge)
        {
            return false;
        }

        return true;
    }

    private static bool FixedTimeEqualsRequired(
        byte[] actual,
        byte[] expected)
    {
        if (actual is null ||
            expected is null)
        {
            return false;
        }

        if (actual.Length == 0 ||
            expected.Length == 0)
        {
            return false;
        }

        if (actual.Length != expected.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            actual,
            expected);
    }
}