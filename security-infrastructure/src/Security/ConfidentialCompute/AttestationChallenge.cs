using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable authoritative attestation challenge.
///
/// Construction and possession grant no authority.
///
/// Mutable binary challenge material is defensively owned:
/// the nonce is copied on ingress and copied again on exposure.
///
/// This object does not generate challenges, consume replay state,
/// verify attestation, authorize workloads, activate a TEE, or grant
/// source-mutation or production authority.
/// </summary>
public sealed class AttestationChallenge
{
    private readonly byte[] _nonce;

    public AttestationChallenge(
        string challengeId,
        byte[] nonce,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        ConfidentialPlatformClass expectedPlatform,
        string workloadBinding)
    {
        if (string.IsNullOrWhiteSpace(challengeId))
        {
            throw new ArgumentException(
                "Challenge identifier must not be empty.",
                nameof(challengeId));
        }

        if (nonce is null)
        {
            throw new ArgumentNullException(nameof(nonce));
        }

        if (nonce.Length == 0)
        {
            throw new ArgumentException(
                "Challenge nonce must not be empty.",
                nameof(nonce));
        }

        if (string.IsNullOrWhiteSpace(workloadBinding))
        {
            throw new ArgumentException(
                "Workload binding must not be empty.",
                nameof(workloadBinding));
        }

        ChallengeId = challengeId;
        _nonce = (byte[])nonce.Clone();
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        ExpectedPlatform = expectedPlatform;
        WorkloadBinding = workloadBinding;
    }

    public string ChallengeId { get; }

    public byte[] Nonce =>
        (byte[])_nonce.Clone();

    public DateTimeOffset IssuedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public ConfidentialPlatformClass ExpectedPlatform { get; }

    public string WorkloadBinding { get; }
}