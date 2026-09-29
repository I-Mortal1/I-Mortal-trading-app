using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Deterministic SHA-256 implementation of the I-Mortal public
/// user-device fingerprint digest.
///
/// This implementation consumes only an already-canonicalized public device
/// identity produced under the K6-C/K6-D canonical serialization contract.
///
/// It does not access a TPM, Secure Enclave, Android Keystore, Linux TPM,
/// private key, credential, developer USB, network service, enrollment
/// service, login service, or authorization service.
///
/// The resulting fingerprint is identification/binding material only.
/// It is not an authentication secret and cannot establish proof of
/// possession of the corresponding hardware-backed private key.
/// </summary>
public sealed class UserDeviceFingerprintDigest
    : IUserDeviceFingerprintDigest
{
    private const string DomainSeparator =
        "I-MORTAL/USER-DEVICE-FINGERPRINT/SHA-256/V1";

    private const int DigestLengthBytes = 32;

    /*
     * This bound is intentionally defensive.
     *
     * K6-D canonical identity records are expected to be small. The digest
     * implementation therefore rejects unreasonably large input rather than
     * allocating attacker-controlled amounts of memory.
     */
    private const int MaximumCanonicalIdentityLengthBytes =
        1024 * 1024;

    private static readonly byte[] DomainSeparatorBytes =
        Encoding.UTF8.GetBytes(DomainSeparator);

    public byte[] ComputeDigest(
        byte[] canonicalDeviceIdentity)
    {
        if (canonicalDeviceIdentity is null)
            throw new ArgumentNullException(
                nameof(canonicalDeviceIdentity));

        if (canonicalDeviceIdentity.Length == 0)
            throw new ArgumentException(
                "Canonical device identity cannot be empty.",
                nameof(canonicalDeviceIdentity));

        if (canonicalDeviceIdentity.Length >
            MaximumCanonicalIdentityLengthBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(canonicalDeviceIdentity),
                "Canonical device identity exceeds the maximum permitted length.");
        }

        checked
        {
            int payloadLength =
                DomainSeparatorBytes.Length +
                1 +
                sizeof(uint) +
                canonicalDeviceIdentity.Length;

            byte[] payload =
                new byte[payloadLength];

            try
            {
                int offset = 0;

                DomainSeparatorBytes.AsSpan().CopyTo(
                    payload.AsSpan(
                        offset,
                        DomainSeparatorBytes.Length));

                offset += DomainSeparatorBytes.Length;

                /*
                 * Explicit domain terminator prevents ambiguous concatenation
                 * between the fixed domain and following binary fields.
                 */
                payload[offset] = 0x00;
                offset += 1;

                BinaryPrimitives.WriteUInt32BigEndian(
                    payload.AsSpan(
                        offset,
                        sizeof(uint)),
                    checked((uint)canonicalDeviceIdentity.Length));

                offset += sizeof(uint);

                canonicalDeviceIdentity.AsSpan().CopyTo(
                    payload.AsSpan(
                        offset,
                        canonicalDeviceIdentity.Length));

                offset += canonicalDeviceIdentity.Length;

                if (offset != payload.Length)
                {
                    throw new CryptographicException(
                        "Fingerprint digest payload construction failed closed.");
                }

                byte[] digest =
                    SHA256.HashData(payload);

                if (digest.Length != DigestLengthBytes)
                {
                    CryptographicOperations.ZeroMemory(digest);

                    throw new CryptographicException(
                        "Unexpected fingerprint digest length.");
                }

                return digest;
            }
            finally
            {
                /*
                 * The payload contains only public canonical identity
                 * material, not private key material. It is still cleared
                 * immediately after use to minimize unnecessary lifetime.
                 */
                CryptographicOperations.ZeroMemory(payload);
            }
        }
    }
}