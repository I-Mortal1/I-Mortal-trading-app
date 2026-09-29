using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class DurabilityEvidence
{
    private readonly byte[] _transactionId;
    private readonly byte[] _stateDigest;
    private readonly byte[] _replayDigest;
    private readonly byte[] _recoveryRecordDigest;
    private readonly byte[] _commitMarkerDigest;

    internal DurabilityEvidence(
        byte[] transactionId,
        byte[] stateDigest,
        byte[] replayDigest,
        byte[] recoveryRecordDigest,
        byte[] commitMarkerDigest,
        VerificationEvidenceBinding binding)
    {
        _transactionId = CopyRequired(
            transactionId,
            nameof(transactionId));

        _stateDigest = CopyRequired(
            stateDigest,
            nameof(stateDigest));

        _replayDigest = CopyRequired(
            replayDigest,
            nameof(replayDigest));

        _recoveryRecordDigest = CopyRequired(
            recoveryRecordDigest,
            nameof(recoveryRecordDigest));

        _commitMarkerDigest = CopyRequired(
            commitMarkerDigest,
            nameof(commitMarkerDigest));

        Binding = binding
            ?? throw new ArgumentNullException(nameof(binding));
    }

    public byte[] TransactionId =>
        (byte[])_transactionId.Clone();

    public byte[] StateDigest =>
        (byte[])_stateDigest.Clone();

    public byte[] ReplayDigest =>
        (byte[])_replayDigest.Clone();

    public byte[] RecoveryRecordDigest =>
        (byte[])_recoveryRecordDigest.Clone();

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
