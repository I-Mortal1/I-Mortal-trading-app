using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class RecoveryRecordIntegrityVerification
{
    private readonly byte[] _verifiedIntegrityDigest;

    internal RecoveryRecordIntegrityVerification(
        Guid transactionId,
        byte[] verifiedIntegrityDigest)
    {
        if (transactionId == Guid.Empty)
        {
            throw new ArgumentException(
                "Transaction identifier must not be empty.",
                nameof(transactionId));
        }

        if (verifiedIntegrityDigest is null)
        {
            throw new ArgumentNullException(
                nameof(verifiedIntegrityDigest));
        }

        if (verifiedIntegrityDigest.Length == 0)
        {
            throw new ArgumentException(
                "Verified integrity digest must not be empty.",
                nameof(verifiedIntegrityDigest));
        }

        TransactionId = transactionId;
        _verifiedIntegrityDigest =
            (byte[])verifiedIntegrityDigest.Clone();
    }

    public Guid TransactionId { get; }

    public byte[] VerifiedIntegrityDigest =>
        (byte[])_verifiedIntegrityDigest.Clone();
}
