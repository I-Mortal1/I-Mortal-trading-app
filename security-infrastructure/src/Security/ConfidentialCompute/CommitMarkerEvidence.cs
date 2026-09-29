using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class CommitMarkerEvidence
{
    private readonly byte[] _transactionId;
    private readonly byte[] _commitMarkerDigest;

    internal CommitMarkerEvidence(
        byte[] transactionId,
        byte[] commitMarkerDigest,
        VerificationEvidenceBinding binding)
    {
        _transactionId = CopyRequired(
            transactionId,
            nameof(transactionId));

        _commitMarkerDigest = CopyRequired(
            commitMarkerDigest,
            nameof(commitMarkerDigest));

        Binding = binding
            ?? throw new ArgumentNullException(nameof(binding));
    }

    public byte[] TransactionId =>
        (byte[])_transactionId.Clone();

    public byte[] CommitMarkerDigest =>
        (byte[])_commitMarkerDigest.Clone();

    public VerificationEvidenceBinding Binding { get; }

    private static byte[] CopyRequired(
        byte[] value,
        string parameterName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (value.Length == 0)
        {
            throw new ArgumentException(
                "Evidence value must not be empty.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}
