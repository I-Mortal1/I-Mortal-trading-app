using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Untrusted evidence claiming correspondence with an exact VeraCrypt backing
/// source.
///
/// Construction of this object proves nothing and grants no authority.
///
/// The evidence must be independently validated by an
/// IVeraCryptBackingSourceVerifier implementation.
///
/// Raw VeraCrypt passwords, raw private keys, recovery secrets, and plaintext
/// source material must never be placed in this object.
/// </summary>
public sealed class VeraCryptBackingSourceEvidence
{
    private readonly byte[] _observedUsbIdentityDigest;
    private readonly byte[] _challengeBinding;
    private readonly byte[] _backingSourceIdentityDigest;

    public VeraCryptBackingSourceEvidence(
        string challengeId,
        string custodyIdentifier,
        string keyIdentifier,
        string volumeIdentity,
        string keyObjectName,
        byte[] observedUsbIdentityDigest,
        byte[] backingSourceIdentityDigest,
        byte[] challengeBinding,
        DateTimeOffset observedAt)
    {
        ChallengeId = RequireText(
            challengeId,
            nameof(challengeId));

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

        _observedUsbIdentityDigest = CopyRequired(
            observedUsbIdentityDigest,
            nameof(observedUsbIdentityDigest),
            "Observed USB identity digest must not be empty.");

        _backingSourceIdentityDigest = CopyRequired(
            backingSourceIdentityDigest,
            nameof(backingSourceIdentityDigest),
            "Backing-source identity digest must not be empty.");

        _challengeBinding = CopyRequired(
            challengeBinding,
            nameof(challengeBinding),
            "Challenge binding must not be empty.");

        ObservedAt = observedAt;
    }

    public string ChallengeId { get; }

    public string CustodyIdentifier { get; }

    public string KeyIdentifier { get; }

    public string VolumeIdentity { get; }

    public string KeyObjectName { get; }

    public byte[] ObservedUsbIdentityDigest =>
        (byte[])_observedUsbIdentityDigest.Clone();

    public byte[] BackingSourceIdentityDigest =>
        (byte[])_backingSourceIdentityDigest.Clone();

    public byte[] ChallengeBinding =>
        (byte[])_challengeBinding.Clone();

    public DateTimeOffset ObservedAt { get; }

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