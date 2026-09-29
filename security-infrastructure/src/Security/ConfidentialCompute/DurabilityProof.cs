using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class DurabilityProof
{
    private readonly byte[] _resultingStateDigest;
    private readonly byte[] _replayStateDigest;
    private readonly byte[] _commitMarkerDigest;

    internal DurabilityProof(
        Guid transactionId,
        long resultingVersion,
        byte[] resultingStateDigest,
        byte[] replayStateDigest,
        byte[] commitMarkerDigest)
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

        _replayStateDigest =
            CopyRequired(replayStateDigest, nameof(replayStateDigest));

        _commitMarkerDigest =
            CopyRequired(commitMarkerDigest, nameof(commitMarkerDigest));

        TransactionId = transactionId;
        ResultingVersion = resultingVersion;
    }

    public Guid TransactionId { get; }

    public long ResultingVersion { get; }

    public byte[] ResultingStateDigest =>
        (byte[])_resultingStateDigest.Clone();

    public byte[] ReplayStateDigest =>
        (byte[])_replayStateDigest.Clone();

    public byte[] CommitMarkerDigest =>
        (byte[])_commitMarkerDigest.Clone();

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
