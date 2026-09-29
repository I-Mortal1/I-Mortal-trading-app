using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class VeraCryptUsbKeyCustodyDescriptor
{
    private readonly byte[] _authorizedUsbIdentityDigest;

    internal VeraCryptUsbKeyCustodyDescriptor(
        string custodyIdentifier,
        string keyIdentifier,
        byte[] authorizedUsbIdentityDigest,
        string volumeIdentity,
        string keyObjectName)
    {
        CustodyIdentifier = RequireText(
            custodyIdentifier,
            nameof(custodyIdentifier));

        KeyIdentifier = RequireText(
            keyIdentifier,
            nameof(keyIdentifier));

        _authorizedUsbIdentityDigest = CopyRequired(
            authorizedUsbIdentityDigest,
            nameof(authorizedUsbIdentityDigest));

        VolumeIdentity = RequireText(
            volumeIdentity,
            nameof(volumeIdentity));

        KeyObjectName = RequireText(
            keyObjectName,
            nameof(keyObjectName));
    }

    public string CustodyIdentifier { get; }
    public string KeyIdentifier { get; }

    public byte[] AuthorizedUsbIdentityDigest =>
        (byte[])_authorizedUsbIdentityDigest.Clone();

    public string VolumeIdentity { get; }
    public string KeyObjectName { get; }

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
