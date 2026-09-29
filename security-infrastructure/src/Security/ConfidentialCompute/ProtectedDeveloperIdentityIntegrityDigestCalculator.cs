using System;
using System.Security.Cryptography;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Fail-closed SHA-256 integrity-digest calculator for
/// ProtectedDeveloperIdentity.
///
/// The calculator:
///
/// - accepts an immutable ProtectedDeveloperIdentity;
/// - obtains its authoritative canonical representation exclusively through
///   IProtectedDeveloperIdentityCanonicalSerializer;
/// - calculates SHA-256 over exactly those canonical bytes;
/// - returns a newly allocated 32-byte digest;
/// - clears the temporary canonical representation before returning.
///
/// It does not decrypt protected identity fields, access identity-encryption
/// keys, access VeraCrypt key material, perform enrollment or rotation,
/// perform external I/O, register itself, or grant authority.
/// </summary>
public sealed class ProtectedDeveloperIdentityIntegrityDigestCalculator :
    IProtectedDeveloperIdentityIntegrityDigestCalculator
{
    private const int Sha256DigestLength = 32;

    private readonly IProtectedDeveloperIdentityCanonicalSerializer
        _canonicalSerializer;

    public ProtectedDeveloperIdentityIntegrityDigestCalculator(
        IProtectedDeveloperIdentityCanonicalSerializer canonicalSerializer)
    {
        _canonicalSerializer =
            canonicalSerializer ??
            throw new ArgumentNullException(
                nameof(canonicalSerializer));
    }

    public byte[] Calculate(
        ProtectedDeveloperIdentity identity)
    {
        if (identity is null)
        {
            throw new ArgumentNullException(
                nameof(identity));
        }

        byte[]? canonicalBytes = null;

        try
        {
            canonicalBytes =
                _canonicalSerializer.SerializeForIntegrity(
                    identity);

            if (canonicalBytes is null)
            {
                throw new CryptographicException(
                    "Canonical identity representation was null.");
            }

            if (canonicalBytes.Length == 0)
            {
                throw new CryptographicException(
                    "Canonical identity representation was empty.");
            }

            byte[] digest =
                SHA256.HashData(
                    canonicalBytes);

            if (digest.Length != Sha256DigestLength)
            {
                CryptographicOperations.ZeroMemory(
                    digest);

                throw new CryptographicException(
                    "Unexpected SHA-256 digest length.");
            }

            return digest;
        }
        catch
        {
            throw;
        }
        finally
        {
            if (canonicalBytes is not null)
            {
                CryptographicOperations.ZeroMemory(
                    canonicalBytes);
            }
        }
    }
}