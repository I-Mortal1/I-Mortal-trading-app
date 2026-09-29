using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class ProtectedStateCommitResult
{
    private readonly byte[] _committedStateDigest;

    internal ProtectedStateCommitResult(
        bool committed,
        long committedVersion,
        byte[] committedStateDigest)
    {
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

        Committed = committed;
        CommittedVersion = committedVersion;
        _committedStateDigest =
            (byte[])committedStateDigest.Clone();
    }

    public bool Committed { get; }

    public long CommittedVersion { get; }

    public byte[] CommittedStateDigest =>
        (byte[])_committedStateDigest.Clone();
}
