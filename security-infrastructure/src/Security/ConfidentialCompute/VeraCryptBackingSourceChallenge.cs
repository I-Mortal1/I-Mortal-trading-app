using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Non-authoritative challenge for proving the exact VeraCrypt backing source
/// associated with the required developer source-custody object.
///
/// Construction or possession of this challenge grants no authority.
///
/// This contract contains challenge material only. It does not mount,
/// unlock, read, write, modify, or otherwise access a VeraCrypt volume.
/// </summary>
public sealed class VeraCryptBackingSourceChallenge
{
    private readonly byte[] _nonce;
    private readonly byte[] _requiredUsbIdentityDigest;

    public VeraCryptBackingSourceChallenge(
        string challengeId,
        byte[] nonce,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        string custodyIdentifier,
        string keyIdentifier,
        string volumeIdentity,
        string keyObjectName,
        byte[] requiredUsbIdentityDigest)
    {
        ChallengeId = RequireText(
            challengeId,
            nameof(challengeId));

        _nonce = CopyRequired(
            nonce,
            nameof(nonce),
            "Challenge nonce must not be empty.");

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

        KeyObjectName = RequireText(
            keyObjectName,
            nameof(keyObjectName));

        _requiredUsbIdentityDigest = CopyRequired(
            requiredUsbIdentityDigest,
            nameof(requiredUsbIdentityDigest),
            "Required USB identity digest must not be empty.");

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

    public string KeyObjectName { get; }

    public byte[] RequiredUsbIdentityDigest =>
        (byte[])_requiredUsbIdentityDigest.Clone();

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
        string parameterName,
        string errorMessage)
    {
        if (value is null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (value.Length == 0)
        {
            throw new ArgumentException(
                errorMessage,
                parameterName);
        }

        return (byte[])value.Clone();
    }
}