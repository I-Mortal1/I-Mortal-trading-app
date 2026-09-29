using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class ContractEncryptionRequest
{
    private readonly byte[] _plaintextDigest;
    private readonly byte[] _associatedDataDigest;

    internal ContractEncryptionRequest(
        byte[] plaintextDigest,
        byte[] associatedDataDigest,
        VeraCryptUsbKeyCustodyDescriptor custody)
    {
        _plaintextDigest = CopyRequired(
            plaintextDigest,
            nameof(plaintextDigest));

        _associatedDataDigest = CopyRequired(
            associatedDataDigest,
            nameof(associatedDataDigest));

        Custody = custody ??
            throw new ArgumentNullException(nameof(custody));
    }

    public byte[] PlaintextDigest =>
        (byte[])_plaintextDigest.Clone();

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