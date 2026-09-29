using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable normalized evidence produced only after an independent
/// attestation-verification boundary has succeeded.
///
/// This type is evidence, not authorization.
/// It cannot grant production, trading, provider-dispatch, USB,
/// or source-mutation authority.
/// </summary>
public sealed class VerifiedConfidentialComputeEvidence :
    IConfidentialComputeEvidence
{
    internal VerifiedConfidentialComputeEvidence(
        ConfidentialEvidenceOrigin origin,
        ConfidentialPlatformClass platformClass,
        bool teeBoundaryPresent,
        bool remoteAttestationPresent,
        DateTimeOffset attestationIssuedAt,
        DateTimeOffset attestationExpiresAt,
        string measurement,
        string measurementPolicyId,
        string workloadIdentity,
        string platformIdentity,
        string securityPolicyId,
        string signedArtifactDigest)
    {
        Origin = origin;
        PlatformClass = platformClass;
        TeeBoundaryPresent = teeBoundaryPresent;
        RemoteAttestationPresent = remoteAttestationPresent;
        AttestationIssuedAt = attestationIssuedAt;
        AttestationExpiresAt = attestationExpiresAt;

        Measurement =
            RequireValue(measurement, nameof(measurement));

        MeasurementPolicyId =
            RequireValue(measurementPolicyId, nameof(measurementPolicyId));

        WorkloadIdentity =
            RequireValue(workloadIdentity, nameof(workloadIdentity));

        PlatformIdentity =
            RequireValue(platformIdentity, nameof(platformIdentity));

        SecurityPolicyId =
            RequireValue(securityPolicyId, nameof(securityPolicyId));

        SignedArtifactDigest =
            RequireValue(signedArtifactDigest, nameof(signedArtifactDigest));
    }

    public ConfidentialEvidenceOrigin Origin { get; }

    public ConfidentialPlatformClass PlatformClass { get; }

    public bool TeeBoundaryPresent { get; }

    public bool RemoteAttestationPresent { get; }

    public DateTimeOffset AttestationIssuedAt { get; }

    public DateTimeOffset AttestationExpiresAt { get; }

    public string Measurement { get; }

    public string MeasurementPolicyId { get; }

    public string WorkloadIdentity { get; }

    public string PlatformIdentity { get; }

    public string SecurityPolicyId { get; }

    public string SignedArtifactDigest { get; }

    private static string RequireValue(
        string value,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "Security evidence value must not be empty.",
                parameterName);
        }

        return value;
    }
}
