using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Deterministic canonical serializer for an already-created
/// UserDeviceProofOfPossessionChallengeData value.
///
/// SECURITY BOUNDARY:
///
/// - Does not generate challenges.
/// - Does not generate or access keys.
/// - Does not sign.
/// - Does not verify signatures.
/// - Does not authenticate users.
/// - Does not enroll or revoke devices.
/// - Does not perform network I/O.
/// - Does not access TPM, Secure Enclave, Android Keystore, or Linux TPM.
/// - Does not activate TEE or attestation.
/// - Does not grant developer or production authority.
///
/// The output is canonical challenge data only.
///
/// Hardware-backed proof of possession is a separate security operation and
/// must occur behind the I-Mortal confidential identity plane.
/// </summary>
public sealed class UserDeviceProofOfPossessionChallengeCanonicalSerializer
    : IUserDeviceProofOfPossessionChallengeCanonicalSerializer
{
    private static readonly UTF8Encoding StrictUtf8 =
        new(
            encoderShouldEmitUTF8Identifier: false,
            throwOnInvalidBytes: true);

    private const int MaximumStringByteLength = 16 * 1024;

    public byte[] Serialize(
        UserDeviceProofOfPossessionChallengeData challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);

        using var stream = new MemoryStream();

        using var writer = new BinaryWriter(
            stream,
            StrictUtf8,
            leaveOpen: true);

        WriteCanonicalString(
            writer,
            UserDeviceProofOfPossessionChallengeCanonicalSerializationContract.DomainSeparator);

        WriteCanonicalString(
            writer,
            challenge.ContractVersion);

        WriteCanonicalString(
            writer,
            challenge.ProtocolId);

        WriteCanonicalString(
            writer,
            challenge.ChallengeId);

        WriteCanonicalString(
            writer,
            challenge.ChallengeNonce);

        WriteCanonicalString(
            writer,
            challenge.AccountIdentity);

        WriteCanonicalString(
            writer,
            challenge.DeviceFingerprint);

        WriteCanonicalString(
            writer,
            challenge.AuthenticationPurpose);

        WriteInt64BigEndian(
            writer,
            checked(challenge.IssuedAtUnixTimeSeconds * 1000L));

        WriteInt64BigEndian(
            writer,
            checked(challenge.ExpiresAtUnixTimeSeconds * 1000L));

        writer.Flush();

        if (stream.Length <= 0)
        {
            throw new InvalidOperationException(
                "Canonical challenge serialization produced no data.");
        }

        if (stream.Length > int.MaxValue)
        {
            throw new InvalidOperationException(
                "Canonical challenge serialization exceeded maximum size.");
        }

        return stream.ToArray();
    }

    private static void WriteCanonicalString(
        BinaryWriter writer,
        string value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        if (value.Length == 0)
        {
            throw new ArgumentException(
                "Canonical strings must not be empty.",
                nameof(value));
        }

        string normalized =
            value.Normalize(
                NormalizationForm.FormC);

        if (!string.Equals(
                value,
                normalized,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Canonical strings must already be NFC normalized.",
                nameof(value));
        }

        byte[] encoded =
            StrictUtf8.GetBytes(value);

        if (encoded.Length == 0)
        {
            throw new ArgumentException(
                "Canonical strings must not encode to an empty value.",
                nameof(value));
        }

        if (encoded.Length > MaximumStringByteLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                "Canonical string exceeds maximum encoded size.");
        }

        WriteUInt32BigEndian(
            writer,
            checked((uint)encoded.Length));

        writer.Write(encoded);
    }

    private static void WriteUInt32BigEndian(
        BinaryWriter writer,
        uint value)
    {
        ArgumentNullException.ThrowIfNull(writer);

        Span<byte> bytes =
            stackalloc byte[sizeof(uint)];

        BinaryPrimitives.WriteUInt32BigEndian(
            bytes,
            value);

        writer.Write(bytes);
    }

    private static void WriteInt64BigEndian(
        BinaryWriter writer,
        long value)
    {
        ArgumentNullException.ThrowIfNull(writer);

        Span<byte> bytes =
            stackalloc byte[sizeof(long)];

        BinaryPrimitives.WriteInt64BigEndian(
            bytes,
            value);

        writer.Write(bytes);
    }
}