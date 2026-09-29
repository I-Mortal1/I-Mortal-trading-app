using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class ProtectedStateCommitMarker
{
    private readonly byte[] _resultingStateDigest;
    private readonly byte[] _replayTransitionDigest;
    private readonly byte[] _recoveryRecordDigest;
    private readonly byte[] _integrityDigest;

    public ProtectedStateCommitMarker(
        Guid transactionId,
        long resultingVersion,
        byte[] resultingStateDigest,
        byte[] replayTransitionDigest,
        byte[] recoveryRecordDigest,
        byte[] integrityDigest)
    {
        if (transactionId == Guid.Empty)
        {
            throw new ArgumentException(
                "Transaction identifier must not be empty.",
                nameof(transactionId));
        }

        if (resultingVersion < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(resultingVersion));
        }

        _resultingStateDigest =
            CopyRequired(resultingStateDigest, nameof(resultingStateDigest));

        _replayTransitionDigest =
            CopyRequired(replayTransitionDigest, nameof(replayTransitionDigest));

        _recoveryRecordDigest =
            CopyRequired(recoveryRecordDigest, nameof(recoveryRecordDigest));

        _integrityDigest =
            CopyRequired(integrityDigest, nameof(integrityDigest));

        TransactionId = transactionId;
        ResultingVersion = resultingVersion;
    }

    public Guid TransactionId { get; }

    public long ResultingVersion { get; }

    public byte[] ResultingStateDigest =>
        (byte[])_resultingStateDigest.Clone();

    public byte[] ReplayTransitionDigest =>
        (byte[])_replayTransitionDigest.Clone();

    public byte[] RecoveryRecordDigest =>
        (byte[])_recoveryRecordDigest.Clone();

    public byte[] IntegrityDigest =>
        (byte[])_integrityDigest.Clone();

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
                "Digest must not be empty.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}
