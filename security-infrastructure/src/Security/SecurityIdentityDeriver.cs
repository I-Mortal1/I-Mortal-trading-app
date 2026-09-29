using System.Security.Cryptography;
using System.Text;

namespace IMortal.TrustBroker.Security;

public static class SecurityIdentityDeriver
{
    private const string DomainPrefix =
        "I-MORTAL:TRUSTBROKER:SECURITY-IDENTITY:V1:";

    public static string Derive(
        string domain,
        string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        var canonical =
            DomainPrefix +
            domain.Trim() +
            ":" +
            value;

        var digest = SHA256.HashData(
            Encoding.UTF8.GetBytes(canonical));

        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    public static string HashNonce(string nonce)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);

        var digest = SHA256.HashData(
            Encoding.UTF8.GetBytes(
                "I-MORTAL:TRUSTBROKER:REGISTRATION-NONCE:V1:" +
                nonce));

        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    public static string DeriveSecurityInstanceId(
        string userId,
        string registrationNonce)
    {
        return Derive(
            "security-instance",
            userId + ":" + registrationNonce);
    }

    public static string DeriveStorageId(
        string securityInstanceId)
    {
        return Derive(
            "storage",
            securityInstanceId);
    }

    public static string DeriveKeyId(
        string securityInstanceId)
    {
        return Derive(
            "key",
            securityInstanceId);
    }

    public static string DeriveCheckpointId(
        string securityInstanceId)
    {
        return Derive(
            "checkpoint",
            securityInstanceId);
    }
}
