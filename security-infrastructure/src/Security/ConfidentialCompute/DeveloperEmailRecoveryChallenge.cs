using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Non-authoritative developer recovery challenge.
///
/// This type deliberately contains no email-sending behavior and no
/// successful authorization factory.
/// </summary>
public sealed class DeveloperEmailRecoveryChallenge
{
    private readonly byte[] _nonce;

    public DeveloperEmailRecoveryChallenge(
        string challengeId,
        byte[] nonce,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        string developerIdentity,
        string recoveryScope)
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

        DeveloperIdentity = RequireText(
            developerIdentity,
            nameof(developerIdentity));

        RecoveryScope = RequireText(
            recoveryScope,
            nameof(recoveryScope));

        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
    }

    public string ChallengeId { get; }

    public byte[] Nonce =>
        (byte[])_nonce.Clone();

    public DateTimeOffset IssuedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public string DeveloperIdentity { get; }

    public string RecoveryScope { get; }

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