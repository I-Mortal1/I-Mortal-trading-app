using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Non-authoritative data emitted only after an Intel TDX cryptographic
/// verification implementation has validated platform evidence.
///
/// This type is deliberately NOT root trust, authorization, source authority,
/// production authority, trading authority, or measurement-policy acceptance.
///
/// R36-R10 does not provide a public or internal success factory here.
/// A future concrete verifier must own the successful transition.
/// </summary>
public sealed class IntelTdxCryptographicVerification
{
    public string ChallengeId { get; }
    public string WorkloadBinding { get; }
    public string PlatformIdentity { get; }
    public byte[] Measurement { get; }
    public DateTimeOffset AttestationIssuedAt { get; }
    public DateTimeOffset AttestationExpiresAt { get; }
    public string SignedArtifactDigest { get; }

    private IntelTdxCryptographicVerification(
        string challengeId,
        string workloadBinding,
        string platformIdentity,
        byte[] measurement,
        DateTimeOffset attestationIssuedAt,
        DateTimeOffset attestationExpiresAt,
        string signedArtifactDigest)
    {
        ChallengeId = challengeId;
        WorkloadBinding = workloadBinding;
        PlatformIdentity = platformIdentity;
        Measurement = measurement is null
            ? Array.Empty<byte>()
            : (byte[])measurement.Clone();
        AttestationIssuedAt = attestationIssuedAt;
        AttestationExpiresAt = attestationExpiresAt;
        SignedArtifactDigest = signedArtifactDigest;
    }

    public byte[] GetMeasurementCopy()
        => (byte[])Measurement.Clone();
}