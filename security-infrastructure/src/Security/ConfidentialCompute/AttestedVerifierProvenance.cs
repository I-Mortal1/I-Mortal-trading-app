using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class AttestedVerifierProvenance
{
    private readonly byte[] _signature;

    public AttestedVerifierProvenance(
        string verifierWorkloadIdentity,
        string verifierMeasurement,
        string verifierSecurityPolicyId,
        ConfidentialPlatformClass platformClass,
        string challengeId,
        string challengeBindingDigest,
        string verifiedEvidenceDigest,
        string signedArtifactDigest,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        byte[] signature)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(verifierWorkloadIdentity);
        ArgumentException.ThrowIfNullOrWhiteSpace(verifierMeasurement);
        ArgumentException.ThrowIfNullOrWhiteSpace(verifierSecurityPolicyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(challengeId);
        ArgumentException.ThrowIfNullOrWhiteSpace(challengeBindingDigest);
        ArgumentException.ThrowIfNullOrWhiteSpace(verifiedEvidenceDigest);
        ArgumentException.ThrowIfNullOrWhiteSpace(signedArtifactDigest);
        ArgumentNullException.ThrowIfNull(signature);

        if (signature.Length == 0)
        {
            throw new ArgumentException(
                "Signature must not be empty.",
                nameof(signature));
        }

        if (expiresAt <= issuedAt)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiresAt),
                "Expiration must be later than issuance.");
        }

        VerifierWorkloadIdentity = verifierWorkloadIdentity;
        VerifierMeasurement = verifierMeasurement;
        VerifierSecurityPolicyId = verifierSecurityPolicyId;
        PlatformClass = platformClass;
        ChallengeId = challengeId;
        ChallengeBindingDigest = challengeBindingDigest;
        VerifiedEvidenceDigest = verifiedEvidenceDigest;
        SignedArtifactDigest = signedArtifactDigest;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;

        _signature = signature.ToArray();
    }

    public string VerifierWorkloadIdentity { get; }

    public string VerifierMeasurement { get; }

    public string VerifierSecurityPolicyId { get; }

    public ConfidentialPlatformClass PlatformClass { get; }

    public string ChallengeId { get; }

    public string ChallengeBindingDigest { get; }

    public string VerifiedEvidenceDigest { get; }

    public string SignedArtifactDigest { get; }

    public DateTimeOffset IssuedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public byte[] Signature => _signature.ToArray();
}