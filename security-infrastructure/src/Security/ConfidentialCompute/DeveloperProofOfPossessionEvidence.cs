using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Untrusted proof-of-possession evidence.
///
/// Construction of this object does not establish successful proof.
/// Independent cryptographic verification is mandatory.
/// </summary>
public sealed class DeveloperProofOfPossessionEvidence
{
    private readonly byte[] _proof;

    public DeveloperProofOfPossessionEvidence(
        string challengeId,
        string keyIdentifier,
        string custodyIdentifier,
        string volumeIdentity,
        byte[] proof)
    {
        ChallengeId = RequireText(
            challengeId,
            nameof(challengeId));

        KeyIdentifier = RequireText(
            keyIdentifier,
            nameof(keyIdentifier));

        CustodyIdentifier = RequireText(
            custodyIdentifier,
            nameof(custodyIdentifier));

        VolumeIdentity = RequireText(
            volumeIdentity,
            nameof(volumeIdentity));

        _proof = CopyRequired(
            proof,
            nameof(proof));
    }

    public string ChallengeId { get; }

    public string KeyIdentifier { get; }

    public string CustodyIdentifier { get; }

    public string VolumeIdentity { get; }

    public byte[] Proof =>
        (byte[])_proof.Clone();

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
                "Proof must not be empty.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}