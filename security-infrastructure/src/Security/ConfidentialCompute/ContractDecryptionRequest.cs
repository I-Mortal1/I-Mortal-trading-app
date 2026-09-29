using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class ContractDecryptionRequest
{
    private readonly byte[] _envelopeDigest;
    private readonly byte[] _associatedDataDigest;

    internal ContractDecryptionRequest(
        byte[] envelopeDigest,
        byte[] associatedDataDigest,
        VeraCryptUsbKeyCustodyDescriptor custody)
    {
        _envelopeDigest = CopyRequired(
            envelopeDigest,
            nameof(envelopeDigest));

        _associatedDataDigest = CopyRequired(
            associatedDataDigest,
            nameof(associatedDataDigest));

        Custody = custody ??
            throw new ArgumentNullException(nameof(custody));
    }

    public byte[] EnvelopeDigest =>
        (byte[])_envelopeDigest.Clone();

    public byte[] AssociatedDataDigest =>
        (byte[])_associatedDataDigest.Clone();

    public VeraCryptUsbKeyCustodyDescriptor Custody { get; }

    private static byte[] CopyRequired(byte[] value, string name)
    {
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length == 0)
            throw new ArgumentException(
                "Binary value must not be empty.",
                name);

        return (byte[])value.Clone();
    }
}