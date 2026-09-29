using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class CryptographicContractEnvelope
{
    private readonly byte[] _nonce;
    private readonly byte[] _ciphertext;
    private readonly byte[] _authenticationTag;
    private readonly byte[] _associatedDataDigest;

    internal CryptographicContractEnvelope(
        int envelopeVersion,
        string algorithm,
        string keyIdentifier,
        string cryptographicDomain,
        byte[] nonce,
        byte[] ciphertext,
        byte[] authenticationTag,
        byte[] associatedDataDigest)
    {
        if (envelopeVersion <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(envelopeVersion));
        }

        EnvelopeVersion = envelopeVersion;
        Algorithm = RequireText(algorithm, nameof(algorithm));
        KeyIdentifier = RequireText(keyIdentifier, nameof(keyIdentifier));
        CryptographicDomain = RequireText(
            cryptographicDomain,
            nameof(cryptographicDomain));

        _nonce = CopyRequired(nonce, nameof(nonce));
        _ciphertext = CopyRequired(ciphertext, nameof(ciphertext));
        _authenticationTag = CopyRequired(
            authenticationTag,
            nameof(authenticationTag));

        _associatedDataDigest = CopyRequired(
            associatedDataDigest,
            nameof(associatedDataDigest));
    }

    public int EnvelopeVersion { get; }
    public string Algorithm { get; }
    public string KeyIdentifier { get; }
    public string CryptographicDomain { get; }

    public byte[] Nonce => (byte[])_nonce.Clone();

    public byte[] Ciphertext => (byte[])_ciphertext.Clone();

    public byte[] AuthenticationTag =>
        (byte[])_authenticationTag.Clone();

    public byte[] AssociatedDataDigest =>
        (byte[])_associatedDataDigest.Clone();

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
                "Binary value must not be empty.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}
