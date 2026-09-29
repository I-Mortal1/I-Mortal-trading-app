using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Untrusted recovery evidence.
///
/// Merely constructing this object does not establish email verification,
/// identity, freshness, replay protection, cryptographic binding, or
/// recovery authorization.
/// </summary>
public sealed class DeveloperEmailRecoveryEvidence
{
    private readonly byte[] _challengeBinding;

    public DeveloperEmailRecoveryEvidence(
        string challengeId,
        string developerIdentity,
        string verificationReference,
        byte[] challengeBinding,
        DateTimeOffset verifiedAt)
    {
        ChallengeId = RequireText(
            challengeId,
            nameof(challengeId));

        DeveloperIdentity = RequireText(
            developerIdentity,
            nameof(developerIdentity));

        VerificationReference = RequireText(
            verificationReference,
            nameof(verificationReference));

        _challengeBinding = CopyRequired(
            challengeBinding,
            nameof(challengeBinding));

        VerifiedAt = verifiedAt;
    }

    public string ChallengeId { get; }

    public string DeveloperIdentity { get; }

    public string VerificationReference { get; }

    public byte[] ChallengeBinding =>
        (byte[])_challengeBinding.Clone();

    public DateTimeOffset VerifiedAt { get; }

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
                "Binding must not be empty.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}