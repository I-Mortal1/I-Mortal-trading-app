using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Deterministic canonical associated-data serializer for protected developer
/// identity cryptographic custody.
///
/// Every cryptographic identity field is bound to:
///
/// - the I-Mortal associated-data schema;
/// - identity version;
/// - protected identity field classification;
/// - cryptographic domain;
/// - key identifier;
/// - exact VeraCrypt USB custody descriptor;
/// - previous identity-record digest.
///
/// Security properties:
///
/// - explicit field-level binary canonicalization;
/// - fixed domain separation;
/// - fixed schema version;
/// - explicit length framing;
/// - signed integers encoded big-endian;
/// - deterministic strict UTF-8;
/// - no JSON;
/// - no reflection;
/// - no key access;
/// - no encryption or decryption;
/// - no external I/O;
/// - no registration;
/// - no authority decision;
/// - fail closed.
///
/// Serialization is cryptographic binding material only. Successful
/// serialization grants no source-mutation, production, trading,
/// provider-dispatch, signing, recovery, user-runtime, or I-Mortal Security
/// Umbrella root authority.
/// </summary>
public sealed class ProtectedDeveloperIdentityAssociatedDataSerializer :
    IProtectedDeveloperIdentityAssociatedDataSerializer
{
    private const string DomainSeparator =
        "I-MORTAL/PROTECTED-DEVELOPER-IDENTITY/ASSOCIATED-DATA";

    private const int SchemaVersion = 1;

    private const string CompleteUsbIdentityFieldName =
        "COMPLETE-USB-IDENTITY";

    private const string UsbIdNumberFieldName =
        "USB-ID-NUMBER";

    private const string RecoveryEmailFieldName =
        "RECOVERY-EMAIL";

    public byte[] Serialize(
        long identityVersion,
        ProtectedDeveloperIdentityField field,
        string cryptographicDomain,
        string keyIdentifier,
        VeraCryptUsbKeyCustodyDescriptor requiredCustody,
        byte[] previousIdentityRecordDigest)
    {
        if (identityVersion <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(identityVersion),
                "Identity version must be greater than zero.");
        }

        if (string.IsNullOrWhiteSpace(cryptographicDomain))
        {
            throw new ArgumentException(
                "Cryptographic domain must not be null, empty, or whitespace.",
                nameof(cryptographicDomain));
        }

        if (string.IsNullOrWhiteSpace(keyIdentifier))
        {
            throw new ArgumentException(
                "Key identifier must not be null, empty, or whitespace.",
                nameof(keyIdentifier));
        }

        if (requiredCustody is null)
        {
            throw new ArgumentNullException(nameof(requiredCustody));
        }

        if (previousIdentityRecordDigest is null)
        {
            throw new ArgumentNullException(
                nameof(previousIdentityRecordDigest));
        }

        ValidatePreviousIdentityRecordDigest(
            identityVersion,
            previousIdentityRecordDigest);

        string fieldName =
            GetCanonicalFieldName(field);

        using var stream =
            new MemoryStream();

        using var writer =
            new BinaryWriter(
                stream,
                new UTF8Encoding(
                    encoderShouldEmitUTF8Identifier: false,
                    throwOnInvalidBytes: true),
                leaveOpen: true);

        WriteUtf8(
            writer,
            DomainSeparator);

        WriteInt32BigEndian(
            writer,
            SchemaVersion);

        WriteInt64BigEndian(
            writer,
            identityVersion);

        WriteUtf8(
            writer,
            fieldName);

        WriteUtf8(
            writer,
            cryptographicDomain);

        WriteUtf8(
            writer,
            keyIdentifier);

        WriteCustody(
            writer,
            requiredCustody);

        WritePreviousIdentityRecordDigest(
            writer,
            identityVersion,
            previousIdentityRecordDigest);

        writer.Flush();

        return stream.ToArray();
    }

    private static string GetCanonicalFieldName(
        ProtectedDeveloperIdentityField field)
    {
        return field switch
        {
            ProtectedDeveloperIdentityField.CompleteUsbIdentity =>
                CompleteUsbIdentityFieldName,

            ProtectedDeveloperIdentityField.UsbIdNumber =>
                UsbIdNumberFieldName,

            ProtectedDeveloperIdentityField.RecoveryEmail =>
                RecoveryEmailFieldName,

            _ =>
                throw new ArgumentOutOfRangeException(
                    nameof(field),
                    field,
                    "Unknown protected developer identity field.")
        };
    }

    private static void ValidatePreviousIdentityRecordDigest(
        long identityVersion,
        byte[] previousIdentityRecordDigest)
    {
        if (previousIdentityRecordDigest is null)
        {
            throw new ArgumentNullException(
                nameof(previousIdentityRecordDigest));
        }

        if (identityVersion == 1)
        {
            if (previousIdentityRecordDigest.Length != 0)
            {
                throw new ArgumentException(
                    "Identity version 1 must have an empty previous identity-record digest.",
                    nameof(previousIdentityRecordDigest));
            }

            return;
        }

        if (previousIdentityRecordDigest.Length == 0)
        {
            throw new ArgumentException(
                "Identity versions greater than 1 require a previous identity-record digest.",
                nameof(previousIdentityRecordDigest));
        }
    }

    private static void WriteCustody(
        BinaryWriter writer,
        VeraCryptUsbKeyCustodyDescriptor custody)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        if (custody is null)
        {
            throw new ArgumentNullException(nameof(custody));
        }

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
        byte[] digest)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        if (digest is null)
        {
            throw new ArgumentNullException(nameof(digest));
        }

        if (identityVersion == 1)
        {
            if (digest.Length != 0)
            {
                throw new ArgumentException(
                    "Identity version 1 must have an empty previous identity-record digest.",
                    nameof(digest));
            }

            WriteLength(
                writer,
                0);

            return;
        }

        WriteRequiredBytes(
            writer,
            digest);
    }

    private static void WriteUtf8(
        BinaryWriter writer,
        string value)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "Canonical string values must not be null, empty, or whitespace.",
                nameof(value));
        }

        byte[] bytes =
            Encoding.UTF8.GetBytes(value);

        WriteRequiredBytes(
            writer,
            bytes);
    }

    private static void WriteRequiredBytes(
        BinaryWriter writer,
        byte[] value)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        if (value.Length == 0)
        {
            throw new ArgumentException(
                "Canonical binary values must not be empty.",
                nameof(value));
        }

        WriteLength(
            writer,
            value.Length);

        writer.Write(value);
    }

    private static void WriteLength(
        BinaryWriter writer,
        int length)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        WriteInt32BigEndian(
            writer,
            length);
    }

    private static void WriteInt32BigEndian(
        BinaryWriter writer,
        int value)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        Span<byte> buffer =
            stackalloc byte[sizeof(int)];

        BinaryPrimitives.WriteInt32BigEndian(
            buffer,
            value);

        writer.Write(buffer);
    }

    private static void WriteInt64BigEndian(
        BinaryWriter writer,
        long value)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        Span<byte> buffer =
            stackalloc byte[sizeof(long)];

        BinaryPrimitives.WriteInt64BigEndian(
            buffer,
            value);

        writer.Write(buffer);
    }
}