using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Non-authoritative challenge material for developer source-custody
/// proof-of-possession.
///
/// Possession of this object grants no authority.
/// </summary>
public sealed class DeveloperProofOfPossessionChallenge
{
    private readonly byte[] _nonce;

    public DeveloperProofOfPossessionChallenge(
        string challengeId,
        byte[] nonce,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        string custodyIdentifier,
        string keyIdentifier,
        string volumeIdentity)
    {
        ChallengeId = RequireText(
            challengeId,
            nameof(challengeId));

        _nonce = CopyRequired(
            nonce,
            nameof(nonce));

        if (expiresAt <= issuedAt)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiresAt),
                "Expiration must be later than issuance.");
        }

        CustodyIdentifier = RequireText(
            custodyIdentifier,
            nameof(custodyIdentifier));

        KeyIdentifier = RequireText(
            keyIdentifier,
            nameof(keyIdentifier));

        VolumeIdentity = RequireText(
            volumeIdentity,
            nameof(volumeIdentity));

        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
    }

    public string ChallengeId { get; }

    public byte[] Nonce =>
        (byte[])_nonce.Clone();

    public DateTimeOffset IssuedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public string CustodyIdentifier { get; }

    public string KeyIdentifier { get; }

    public string VolumeIdentity { get; }

    private static string RequireText(
        string value,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "Value must not be empty.",
                parameterName);
        }

        return value;
    }

    private static byte[] CopyRequired(
        byte[] value,
        string parameterName)
    {
        if (value is null)
            throw new ArgumentNullException(parameterName);

        if (value.Length == 0)
        {
            throw new ArgumentException(
                "Challenge value must not be empty.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}