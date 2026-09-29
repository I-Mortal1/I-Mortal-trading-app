using System.Buffers.Binary;
using System.Text;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Deterministic canonical serializer for I-MORTAL user-device fingerprint
/// identification/binding material.
///
/// SECURITY BOUNDARY
/// -----------------
///
/// This implementation performs canonical serialization only.
///
/// It does not:
///
/// - hash the canonical representation;
/// - generate a fingerprint digest;
/// - generate, provision, unwrap, export, import, transfer, or synchronize
///   private-key material;
/// - access TPM, Secure Enclave, StrongBox, Android Keystore, Linux TPM,
///   VeraCrypt, or developer USB material;
/// - perform proof-of-possession;
/// - authenticate or authorize a user;
/// - enroll or revoke a device;
/// - generate or scan QR codes;
/// - perform network I/O;
/// - issue a session;
/// - activate TEE or attestation;
/// - grant source access, source mutation, developer authority,
///   signing authority, or production authority.
///
/// Canonical format:
///
///   DOMAIN:
///       UInt32 big-endian byte length
///       UTF-8 domain bytes
///
///   SCHEMA VERSION:
///       UInt32 big-endian value = 1
///
///   VARIABLE FIELDS:
///       UInt32 big-endian byte length
///       exact field bytes
///
/// Field order:
///
///   1. accountIdentity
///   2. publicKeyAlgorithm
///   3. canonicalPublicKey
///   4. platformClass
///   5. providerClass
///   6. keyPurpose
///
/// Strings are encoded as strict UTF-8 without a BOM.
///
/// Null, empty, whitespace-only, malformed Unicode, oversized, or otherwise
/// invalid input fails closed.
///
/// The returned bytes are fingerprint-input material only. They are not a
/// password, private key, bearer credential, authentication decision,
/// authorization decision, or proof-of-possession.
/// </summary>
public sealed class UserDeviceFingerprintCanonicalSerializer
    : IUserDeviceFingerprintCanonicalSerializer
{
    private const string DomainSeparator =
        "I-MORTAL/USER-DEVICE-FINGERPRINT/V1";

    private const uint SchemaVersion = 1;

    /*
     * Defensive allocation bound for canonical public-key material.
     *
     * This serializer is intended for public-key representations, not
     * arbitrary payloads. The bound prevents unreasonable allocations while
     * remaining independent of any specific future approved public-key
     * algorithm.
     */
    private const int MaximumCanonicalPublicKeyLength = 16 * 1024;

    /*
     * Defensive UTF-8 field bound.
     */
    private const int MaximumUtf8FieldLength = 4 * 1024;

    private static readonly UTF8Encoding StrictUtf8 =
        new(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true);

    public byte[] Serialize(
        string accountIdentity,
        string publicKeyAlgorithm,
        byte[] canonicalPublicKey,
        string platformClass,
        string providerClass,
        string keyPurpose)
    {
        byte[]? domainBytes = null;
        byte[]? accountBytes = null;
        byte[]? algorithmBytes = null;
        byte[]? platformBytes = null;
        byte[]? providerBytes = null;
        byte[]? purposeBytes = null;

        try
        {
            domainBytes =
                EncodeRequiredString(
                    DomainSeparator,
                    nameof(DomainSeparator));

            accountBytes =
                EncodeRequiredString(
                    accountIdentity,
                    nameof(accountIdentity));

            algorithmBytes =
                EncodeRequiredString(
                    publicKeyAlgorithm,
                    nameof(publicKeyAlgorithm));

            ValidateCanonicalPublicKey(canonicalPublicKey);

            platformBytes =
                EncodeRequiredString(
                    platformClass,
                    nameof(platformClass));

            providerBytes =
                EncodeRequiredString(
                    providerClass,
                    nameof(providerClass));

            purposeBytes =
                EncodeRequiredString(
                    keyPurpose,
                    nameof(keyPurpose));

            int totalLength = checked(
                LengthPrefixedSize(domainBytes.Length) +
                sizeof(uint) +
                LengthPrefixedSize(accountBytes.Length) +
                LengthPrefixedSize(algorithmBytes.Length) +
                LengthPrefixedSize(canonicalPublicKey.Length) +
                LengthPrefixedSize(platformBytes.Length) +
                LengthPrefixedSize(providerBytes.Length) +
                LengthPrefixedSize(purposeBytes.Length));

            byte[] output = new byte[totalLength];

            int offset = 0;

            offset =
                WriteLengthPrefixed(
                    output,
                    offset,
                    domainBytes);

            WriteUInt32BigEndian(
                output,
                offset,
                SchemaVersion);

            offset += sizeof(uint);

            offset =
                WriteLengthPrefixed(
                    output,
                    offset,
                    accountBytes);

            offset =
                WriteLengthPrefixed(
                    output,
                    offset,
                    algorithmBytes);

            offset =
                WriteLengthPrefixed(
                    output,
                    offset,
                    canonicalPublicKey);

            offset =
                WriteLengthPrefixed(
                    output,
                    offset,
                    platformBytes);

            offset =
                WriteLengthPrefixed(
                    output,
                    offset,
                    providerBytes);

            offset =
                WriteLengthPrefixed(
                    output,
                    offset,
                    purposeBytes);

            if (offset != output.Length)
            {
                Array.Clear(output, 0, output.Length);

                throw new InvalidOperationException(
                    "Canonical serialization length invariant failed.");
            }

            return output;
        }
        catch (ArgumentException)
        {
            /*
             * Preserve explicit fail-closed input-validation exceptions.
             *
             * EncoderFallbackException is translated to ArgumentException
             * inside EncodeRequiredString, so no separate outer
             * EncoderFallbackException catch is required or permitted here.
             */
            throw;
        }
        catch (OverflowException ex)
        {
            throw new ArgumentException(
                "Canonical fingerprint input exceeds permitted bounds.",
                ex);
        }
        catch (Exception ex)
        {
            /*
             * Fail closed while retaining an explicit error rather than
             * returning partial or ambiguous canonical data.
             */
            throw new InvalidOperationException(
                "User-device fingerprint canonical serialization failed closed.",
                ex);
        }
    }

    private static byte[] EncodeRequiredString(
        string value,
        string parameterName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "Canonical string input must not be empty or whitespace.",
                parameterName);
        }

        /*
         * Canonical inputs must already be Unicode NFC.
         *
         * Reject rather than silently normalize so that the serializer never
         * silently changes security-relevant identity input.
         */
        if (!value.IsNormalized(NormalizationForm.FormC))
        {
            throw new ArgumentException(
                "Canonical string input must already be Unicode NFC.",
                parameterName);
        }

        byte[] encoded;

        try
        {
            encoded = StrictUtf8.GetBytes(value);
        }
        catch (EncoderFallbackException ex)
        {
            throw new ArgumentException(
                "Canonical string input contains invalid Unicode.",
                parameterName,
                ex);
        }

        if (encoded.Length == 0)
        {
            throw new ArgumentException(
                "Canonical UTF-8 field must not be empty.",
                parameterName);
        }

        if (encoded.Length > MaximumUtf8FieldLength)
        {
            Array.Clear(encoded, 0, encoded.Length);

            throw new ArgumentException(
                "Canonical UTF-8 field exceeds the permitted size.",
                parameterName);
        }

        return encoded;
    }

    private static void ValidateCanonicalPublicKey(
        byte[] canonicalPublicKey)
    {
        if (canonicalPublicKey is null)
        {
            throw new ArgumentNullException(
                nameof(canonicalPublicKey));
        }

        if (canonicalPublicKey.Length == 0)
        {
            throw new ArgumentException(
                "Canonical public key must not be empty.",
                nameof(canonicalPublicKey));
        }

        if (canonicalPublicKey.Length >
            MaximumCanonicalPublicKeyLength)
        {
            throw new ArgumentException(
                "Canonical public key exceeds the permitted size.",
                nameof(canonicalPublicKey));
        }
    }

    private static int LengthPrefixedSize(
        int payloadLength)
    {
        if (payloadLength <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(payloadLength));
        }

        return checked(sizeof(uint) + payloadLength);
    }

    private static int WriteLengthPrefixed(
        byte[] destination,
        int offset,
        byte[] value)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length == 0)
        {
            throw new ArgumentException(
                "Length-prefixed canonical field must not be empty.",
                nameof(value));
        }

        if (offset < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(offset));
        }

        int requiredLength =
            checked(sizeof(uint) + value.Length);

        if (offset > destination.Length - requiredLength)
        {
            throw new ArgumentException(
                "Canonical destination buffer is too small.",
                nameof(destination));
        }

        WriteUInt32BigEndian(
            destination,
            offset,
            checked((uint)value.Length));

        offset += sizeof(uint);

        value.AsSpan().CopyTo(
            destination.AsSpan(
                offset,
                value.Length));

        return checked(offset + value.Length);
    }

    private static void WriteUInt32BigEndian(
        byte[] destination,
        int offset,
        uint value)
    {
        ArgumentNullException.ThrowIfNull(destination);

        if (offset < 0 ||
            offset > destination.Length - sizeof(uint))
        {
            throw new ArgumentOutOfRangeException(
                nameof(offset));
        }

        BinaryPrimitives.WriteUInt32BigEndian(
            destination.AsSpan(
                offset,
                sizeof(uint)),
            value);
    }
}