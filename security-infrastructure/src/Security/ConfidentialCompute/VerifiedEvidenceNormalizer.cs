using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Controlled transition from independently verified normalized evidence
/// into the immutable verified-evidence representation.
///
/// IMPORTANT:
/// This component does not cryptographically verify TDX or SEV-SNP evidence.
/// A real platform verifier must establish verification before invoking this
/// internal boundary.
///
/// This component does not grant root trust or operational authority.
/// </summary>
internal static class VerifiedEvidenceNormalizer
{
    internal static VerifiedAttestationResult NormalizeVerified(
        IConfidentialComputeEvidence evidence,
        DateTimeOffset now)
    {
        if (evidence is null)
        {
            return VerifiedAttestationResult.Denied(
                "Evidence is missing.");
        }

        if (evidence.Origin != ConfidentialEvidenceOrigin.Production)
        {
            return VerifiedAttestationResult.Denied(
                "Evidence origin is not production.");
        }

        if (!IsSupportedPlatform(evidence.PlatformClass))
        {
            return VerifiedAttestationResult.Denied(
                "Confidential-compute platform is not supported.");
        }

        if (!evidence.TeeBoundaryPresent)
        {
            return VerifiedAttestationResult.Denied(
                "TEE boundary is absent.");
        }

        if (!evidence.RemoteAttestationPresent)
        {
            return VerifiedAttestationResult.Denied(
                "Remote attestation is absent.");
        }

        if (evidence.AttestationIssuedAt > now)
        {
            return VerifiedAttestationResult.Denied(
                "Attestation issue time is in the future.");
        }

        if (evidence.AttestationExpiresAt <= now)
        {
            return VerifiedAttestationResult.Denied(
                "Attestation is expired.");
        }

        if (evidence.AttestationExpiresAt <= evidence.AttestationIssuedAt)
        {
            return VerifiedAttestationResult.Denied(
                "Attestation validity interval is invalid.");
        }

        if (!HasValue(evidence.Measurement) ||
            !HasValue(evidence.MeasurementPolicyId) ||
            !HasValue(evidence.WorkloadIdentity) ||
            !HasValue(evidence.PlatformIdentity) ||
            !HasValue(evidence.SecurityPolicyId) ||
            !HasValue(evidence.SignedArtifactDigest))
        {
            return VerifiedAttestationResult.Denied(
                "Required normalized evidence field is absent.");
        }

        var normalized =
            new VerifiedConfidentialComputeEvidence(
                evidence.Origin,
                evidence.PlatformClass,
                evidence.TeeBoundaryPresent,
                evidence.RemoteAttestationPresent,
                evidence.AttestationIssuedAt,
                evidence.AttestationExpiresAt,
                evidence.Measurement,
                evidence.MeasurementPolicyId,
                evidence.WorkloadIdentity,
                evidence.PlatformIdentity,
                evidence.SecurityPolicyId,
                evidence.SignedArtifactDigest);

        return VerifiedAttestationResult.Success(normalized);
    }

    private static bool IsSupportedPlatform(
        ConfidentialPlatformClass platform)
    {
        return platform == ConfidentialPlatformClass.IntelTdx ||
               platform == ConfidentialPlatformClass.AmdSevSnp;
    }

    private static bool HasValue(string? value)
    {
        return !string.IsNullOrWhiteSpace(value);
    }
}
