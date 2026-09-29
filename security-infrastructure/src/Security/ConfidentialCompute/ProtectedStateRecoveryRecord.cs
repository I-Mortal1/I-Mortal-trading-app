using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class ProtectedStateRecoveryRecord
{
    private readonly byte[] _expectedCurrentStateDigest;
    private readonly byte[] _authorizedChangesetDigest;
    private readonly byte[] _resultingStateDigest;
    private readonly byte[] _replayTransitionDigest;
    private readonly byte[] _integrityDigest;

    public ProtectedStateRecoveryRecord(
        Guid transactionId,
        long expectedCurrentVersion,
        byte[] expectedCurrentStateDigest,
        byte[] authorizedChangesetDigest,
        long resultingVersion,
        byte[] resultingStateDigest,
        byte[] replayTransitionDigest,
        ConfidentialSecurityBoundaryIdentity boundaryIdentity,
        ProtectedStateTransactionPhase phase,
        byte[] integrityDigest)
    {
        if (transactionId == Guid.Empty)
        {
            throw new ArgumentException(
                "Transaction identifier must not be empty.",
                nameof(transactionId));
        }

        if (expectedCurrentVersion < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedCurrentVersion));
        }

        if (resultingVersion <= expectedCurrentVersion)
        {
            throw new ArgumentOutOfRangeException(
                nameof(resultingVersion));
        }

        if (phase == ProtectedStateTransactionPhase.None)
        {
            throw new ArgumentOutOfRangeException(nameof(phase));
        }

        TransactionId = transactionId;
        ExpectedCurrentVersion = expectedCurrentVersion;

        _expectedCurrentStateDigest = CopyRequired(
            expectedCurrentStateDigest,
            nameof(expectedCurrentStateDigest));

        _authorizedChangesetDigest = CopyRequired(
            authorizedChangesetDigest,
            nameof(authorizedChangesetDigest));

        ResultingVersion = resultingVersion;

        _resultingStateDigest = CopyRequired(
            resultingStateDigest,
            nameof(resultingStateDigest));

        _replayTransitionDigest = CopyRequired(
            replayTransitionDigest,
            nameof(replayTransitionDigest));

        BoundaryIdentity = boundaryIdentity
            ?? throw new ArgumentNullException(nameof(boundaryIdentity));

        Phase = phase;

        _integrityDigest = CopyRequired(
            integrityDigest,
            nameof(integrityDigest));
    }

    public Guid TransactionId { get; }

    public long ExpectedCurrentVersion { get; }

    public byte[] ExpectedCurrentStateDigest =>
        (byte[])_expectedCurrentStateDigest.Clone();

    public byte[] AuthorizedChangesetDigest =>
        (byte[])_authorizedChangesetDigest.Clone();

    public long ResultingVersion { get; }

    public byte[] ResultingStateDigest =>
        (byte[])_resultingStateDigest.Clone();

    public byte[] ReplayTransitionDigest =>
        (byte[])_replayTransitionDigest.Clone();

    public ConfidentialSecurityBoundaryIdentity BoundaryIdentity { get; }

    public ProtectedStateTransactionPhase Phase { get; }

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