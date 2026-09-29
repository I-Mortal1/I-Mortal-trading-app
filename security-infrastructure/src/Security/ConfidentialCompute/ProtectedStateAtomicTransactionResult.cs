using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class ProtectedStateAtomicTransactionResult
{
    private readonly byte[] _committedStateDigest;

    internal ProtectedStateAtomicTransactionResult(
        bool committed,
        long committedVersion,
        byte[] committedStateDigest)
    {
        if (!committed)
        {
            throw new ArgumentException(
                "An atomic transaction result may only represent a completed durable commit.",
                nameof(committed));
        }

        if (committedVersion < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(committedVersion));
        }

        if (committedStateDigest is null)
        {
            throw new ArgumentNullException(
                nameof(committedStateDigest));
        }

        if (committedStateDigest.Length == 0)
        {
            throw new ArgumentException(
                "Committed state digest must not be empty.",
                nameof(committedStateDigest));
        }

        Committed = true;
        CommittedVersion = committedVersion;

        _committedStateDigest =
            (byte[])committedStateDigest.Clone();
    }

    public bool Committed { get; }

    public long CommittedVersion { get; }

    public byte[] CommittedStateDigest =>
        (byte[])_committedStateDigest.Clone();
}