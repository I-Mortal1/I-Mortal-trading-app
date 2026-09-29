using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class TrustedProducerContext
{
    private readonly byte[] _protectedStateDigest;
    private readonly byte[] _producerMeasurementDigest;

    internal TrustedProducerContext(
        long protectedStateVersion,
        byte[] protectedStateDigest,
        byte[] producerMeasurementDigest,
        string confidentialBoundaryIdentifier)
    {
        if (protectedStateVersion < 0)
            throw new ArgumentOutOfRangeException(nameof(protectedStateVersion));

        ProtectedStateVersion = protectedStateVersion;

        _protectedStateDigest = CopyRequired(
            protectedStateDigest,
            nameof(protectedStateDigest));

        _producerMeasurementDigest = CopyRequired(
            producerMeasurementDigest,
            nameof(producerMeasurementDigest));

        if (string.IsNullOrWhiteSpace(confidentialBoundaryIdentifier))
            throw new ArgumentException(
                "Confidential boundary identifier is required.",
                nameof(confidentialBoundaryIdentifier));

        ConfidentialBoundaryIdentifier = confidentialBoundaryIdentifier;
    }

    public long ProtectedStateVersion { get; }

    public byte[] ProtectedStateDigest =>
        (byte[])_protectedStateDigest.Clone();

    public byte[] ProducerMeasurementDigest =>
        (byte[])_producerMeasurementDigest.Clone();

    public string ConfidentialBoundaryIdentifier { get; }

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