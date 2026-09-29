using System;
using System.IO;
using System.Text;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Deterministic field-level binary canonical serializer for
/// ProtectedDeveloperIdentity.
///
/// Security properties:
///
/// - fixed domain separation;
/// - fixed schema version;
/// - explicit field ordering;
/// - explicit length framing;
/// - deterministic UTF-8 encoding;
/// - explicit big-endian integer encoding;
/// - IdentityVersion preserved as signed 64-bit value;
/// - version 1 explicitly permits an empty previous-record digest;
/// - non-initial identities require the contract-enforced previous digest;
/// - no JSON;
/// - no reflection;
/// - no culture-dependent formatting;
/// - no property enumeration;
/// - every security-relevant field of each cryptographic envelope is
///   serialized explicitly;
/// - every security-relevant field of the VeraCrypt custody descriptor is
///   serialized explicitly;
/// - IdentityRecordIntegrityDigest is deliberately excluded from its own input;
/// - no plaintext identity recovery;
/// - no key access;
/// - no external I/O;
/// - fail closed.
/// </summary>
public sealed class ProtectedDeveloperIdentityCanonicalSerializer :
    IProtectedDeveloperIdentityCanonicalSerializer
{
    private const string DomainSeparator =
        "I-MORTAL/PROTECTED-DEVELOPER-IDENTITY/INTEGRITY";

    private const int SchemaVersion = 1;

    private static readonly UTF8Encoding StrictUtf8 =
        new(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true);

    public byte[] SerializeForIntegrity(
        ProtectedDeveloperIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        using var stream = new MemoryStream();

        using var writer =
            new BinaryWriter(
                stream,
                StrictUtf8,
                leaveOpen: true);

        WriteUtf8(
            writer,
            DomainSeparator);

        WriteInt32BigEndian(
            writer,
            SchemaVersion);

        WriteInt64BigEndian(
            writer,
            identity.IdentityVersion);

        WriteEnvelope(
            writer,
            identity.CompleteUsbIdentityEnvelope);

        WriteRequiredBytes(
            writer,
            identity.CompleteUsbIdentityCommitment);

        WriteEnvelope(
            writer,
            identity.UsbIdNumberEnvelope);

        WriteRequiredBytes(
            writer,
            identity.UsbIdNumberCommitment);

        WriteEnvelope(
            writer,
            identity.RecoveryEmailEnvelope);

        WriteRequiredBytes(
            writer,
            identity.RecoveryEmailCommitment);

        WriteCustody(
            writer,
            identity.RequiredUsbCustody);

        WritePreviousIdentityRecordDigest(
            writer,
            identity.IdentityVersion,
            identity.PreviousIdentityRecordDigest);

        writer.Flush();

        return stream.ToArray();
    }

    private static void WriteEnvelope(
        BinaryWriter writer,
        CryptographicContractEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(envelope);

        WriteInt32BigEndian(
            writer,
            envelope.EnvelopeVersion);

        WriteUtf8(
            writer,
            envelope.Algorithm);

        WriteUtf8(
            writer,
            envelope.KeyIdentifier);

        WriteUtf8(
            writer,
            envelope.CryptographicDomain);

        WriteRequiredBytes(
            writer,
            envelope.Nonce);

        WriteRequiredBytes(
            writer,
            envelope.Ciphertext);

        WriteRequiredBytes(
            writer,
            envelope.AuthenticationTag);

        WriteRequiredBytes(
            writer,
            envelope.AssociatedDataDigest);
    }

    private static void WriteCustody(
        BinaryWriter writer,
        VeraCryptUsbKeyCustodyDescriptor custody)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(custody);

        WriteUtf8(
            writer,
            custody.CustodyIdentifier);

        WriteUtf8(
            writer,
            custody.KeyIdentifier);

        WriteRequiredBytes(
            writer,
            custody.AuthorizedUsbIdentityDigest);

        WriteUtf8(
            writer,
            custody.VolumeIdentity);

        WriteUtf8(
            writer,
            custody.KeyObjectName);
    }

    private static void WritePreviousIdentityRecordDigest(
        BinaryWriter writer,
        long identityVersion,
        byte[] value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        if (identityVersion <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(identityVersion),
                "Protected developer identity version must be positive.");
        }

        if (identityVersion == 1)
        {
            if (value.Length != 0)
            {
                throw new ArgumentException(
                    "Initial protected identity must have an empty previous-record digest.",
                    nameof(value));
            }

            WriteLengthPrefixedBytesAllowEmpty(
                writer,
                value);

            return;
        }

        if (value.Length == 0)
        {
            throw new ArgumentException(
                "Non-initial protected identity must have a previous-record digest.",
                nameof(value));
        }

        WriteRequiredBytes(
            writer,
            value);
    }

    private static void WriteUtf8(
        BinaryWriter writer,
        string value)
    {
        ArgumentNullException.ThrowIfNull(writer);

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "Canonical text value must not be null, empty, or whitespace.",
                nameof(value));
        }

        byte[] bytes =
            StrictUtf8.GetBytes(value);

        WriteRequiredBytes(
            writer,
            bytes);
    }

    private static void WriteRequiredBytes(
        BinaryWriter writer,
        byte[] value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length == 0)
        {
            throw new ArgumentException(
                "Canonical binary value must not be empty.",
                nameof(value));
        }

        WriteLengthPrefixedBytesAllowEmpty(
            writer,
            value);
    }

    private static void WriteLengthPrefixedBytesAllowEmpty(
        BinaryWriter writer,
        byte[] value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        WriteInt32BigEndian(
            writer,
            value.Length);

        if (value.Length > 0)
        {
            writer.Write(value);
        }
    }

    private static void WriteInt32BigEndian(
        BinaryWriter writer,
        int value)
    {
        ArgumentNullException.ThrowIfNull(writer);

        Span<byte> encoded =
            stackalloc byte[sizeof(int)];

        unchecked
        {
            encoded[0] = (byte)(value >> 24);
            encoded[1] = (byte)(value >> 16);
            encoded[2] = (byte)(value >> 8);
            encoded[3] = (byte)value;
        }

        writer.Write(encoded);
    }

    private static void WriteInt64BigEndian(
        BinaryWriter writer,
        long value)
    {
        ArgumentNullException.ThrowIfNull(writer);

        Span<byte> encoded =
            stackalloc byte[sizeof(long)];

        unchecked
        {
            encoded[0] = (byte)(value >> 56);
            encoded[1] = (byte)(value >> 48);
            encoded[2] = (byte)(value >> 40);
            encoded[3] = (byte)(value >> 32);
            encoded[4] = (byte)(value >> 24);
            encoded[5] = (byte)(value >> 16);
            encoded[6] = (byte)(value >> 8);
            encoded[7] = (byte)value;
        }

        writer.Write(encoded);
    }
}