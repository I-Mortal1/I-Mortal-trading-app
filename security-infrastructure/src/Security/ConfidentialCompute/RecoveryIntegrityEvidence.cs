using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class RecoveryIntegrityEvidence
{
    private readonly byte[] _recoveryRecordDigest;
    private readonly byte[] _expectedIntegrityDigest;

    internal RecoveryIntegrityEvidence(
        byte[] recoveryRecordDigest,
        byte[] expectedIntegrityDigest,
        VerificationEvidenceBinding binding)
    {
        _recoveryRecordDigest = CopyRequired(
            recoveryRecordDigest,
            nameof(recoveryRecordDigest));

        _expectedIntegrityDigest = CopyRequired(
            expectedIntegrityDigest,
            nameof(expectedIntegrityDigest));

        Binding = binding
            ?? throw new ArgumentNullException(nameof(binding));
    }

    public byte[] RecoveryRecordDigest =>
        (byte[])_recoveryRecordDigest.Clone();

    public byte[] ExpectedIntegrityDigest =>
        (byte[])_expectedIntegrityDigest.Clone();

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
                "Digest must not be empty.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}
