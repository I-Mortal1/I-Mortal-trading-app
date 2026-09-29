using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class TrustedProducerProvenance
{
    private readonly byte[] _protectedStateDigest;
    private readonly byte[] _measurementPolicyDigest;
    private readonly byte[] _attestationContextDigest;

    internal TrustedProducerProvenance(
        string producerIdentity,
        string producerVersion,
        string contractIdentity,
        string contractVersion,
        long protectedStateVersion,
        byte[] protectedStateDigest,
        ConfidentialSecurityBoundaryIdentity boundaryIdentity,
        byte[] measurementPolicyDigest,
        byte[] attestationContextDigest,
        string cryptographicDomain,
        int envelopeFormatVersion,
        string keyIdentifier,
        string purpose)
    {
        ProducerIdentity = RequireText(producerIdentity, nameof(producerIdentity));
        ProducerVersion = RequireText(producerVersion, nameof(producerVersion));
        ContractIdentity = RequireText(contractIdentity, nameof(contractIdentity));
        ContractVersion = RequireText(contractVersion, nameof(contractVersion));

        if (protectedStateVersion < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(protectedStateVersion));
        }

        ProtectedStateVersion = protectedStateVersion;
        _protectedStateDigest = CopyRequired(
            protectedStateDigest,
            nameof(protectedStateDigest));

        BoundaryIdentity = boundaryIdentity
            ?? throw new ArgumentNullException(nameof(boundaryIdentity));

        _measurementPolicyDigest = CopyRequired(
            measurementPolicyDigest,
            nameof(measurementPolicyDigest));

        _attestationContextDigest = CopyRequired(
            attestationContextDigest,
            nameof(attestationContextDigest));

        CryptographicDomain = RequireText(
            cryptographicDomain,
            nameof(cryptographicDomain));

        if (envelopeFormatVersion <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(envelopeFormatVersion));
        }

        EnvelopeFormatVersion = envelopeFormatVersion;
        KeyIdentifier = RequireText(keyIdentifier, nameof(keyIdentifier));
        Purpose = RequireText(purpose, nameof(purpose));
    }

    public string ProducerIdentity { get; }
    public string ProducerVersion { get; }
    public string ContractIdentity { get; }
    public string ContractVersion { get; }
    public long ProtectedStateVersion { get; }

    public byte[] ProtectedStateDigest =>
        (byte[])_protectedStateDigest.Clone();

    public ConfidentialSecurityBoundaryIdentity BoundaryIdentity { get; }

    public byte[] MeasurementPolicyDigest =>
        (byte[])_measurementPolicyDigest.Clone();

    public byte[] AttestationContextDigest =>
        (byte[])_attestationContextDigest.Clone();

    public string CryptographicDomain { get; }
    public int EnvelopeFormatVersion { get; }
    public string KeyIdentifier { get; }
    public string Purpose { get; }

    private static string RequireText(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "Value must not be empty.",
                parameterName);
        }

        return value;
    }

    private static byte[] CopyRequired(byte[] value, string parameterName)
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
