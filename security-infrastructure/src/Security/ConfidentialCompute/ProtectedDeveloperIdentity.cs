using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable cryptographically protected representation of the canonical
/// developer identity governed by the I-Mortal Security Umbrella.
///
/// This record MUST NOT contain plaintext representations of:
///
/// - the complete canonical USB identity,
/// - the canonical USB identification number,
/// - the canonical developer recovery email address.
///
/// Each protected identity component consists of:
///
/// - an authenticated-encryption envelope containing the confidential value;
/// - a keyed cryptographic commitment suitable for equality and binding
///   verification without exposing the confidential value.
///
/// This object is identity/custody evidence only.
///
/// Possession, construction, validation, decryption, or successful comparison
/// of this object does not independently grant source-mutation authority,
/// production authority, signing authority, trading authority,
/// provider-dispatch authority, user-runtime authority, or I-Mortal Security
/// Umbrella root authority.
///
/// Identity replacement or rotation must occur only through an explicitly
/// authorized protected-state transition.
///
/// Consumers must fail closed.
/// </summary>
public sealed class ProtectedDeveloperIdentity
{
    private const int CryptographicDigestLength = 32;

    private readonly byte[] _completeUsbIdentityCommitment;
    private readonly byte[] _usbIdNumberCommitment;
    private readonly byte[] _recoveryEmailCommitment;
    private readonly byte[] _previousIdentityRecordDigest;
    private readonly byte[] _identityRecordIntegrityDigest;

    public ProtectedDeveloperIdentity(
        long identityVersion,
        CryptographicContractEnvelope completeUsbIdentityEnvelope,
        byte[] completeUsbIdentityCommitment,
        CryptographicContractEnvelope usbIdNumberEnvelope,
        byte[] usbIdNumberCommitment,
        CryptographicContractEnvelope recoveryEmailEnvelope,
        byte[] recoveryEmailCommitment,
        VeraCryptUsbKeyCustodyDescriptor requiredUsbCustody,
        byte[] previousIdentityRecordDigest,
        byte[] identityRecordIntegrityDigest)
    {
        if (identityVersion <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(identityVersion),
                "Protected developer identity version must be positive.");
        }

        CompleteUsbIdentityEnvelope =
            completeUsbIdentityEnvelope
            ?? throw new ArgumentNullException(
                nameof(completeUsbIdentityEnvelope));

        UsbIdNumberEnvelope =
            usbIdNumberEnvelope
            ?? throw new ArgumentNullException(
                nameof(usbIdNumberEnvelope));

        RecoveryEmailEnvelope =
            recoveryEmailEnvelope
            ?? throw new ArgumentNullException(
                nameof(recoveryEmailEnvelope));

        RequiredUsbCustody =
            requiredUsbCustody
            ?? throw new ArgumentNullException(
                nameof(requiredUsbCustody));

        _completeUsbIdentityCommitment =
            CopyRequiredDigest(
                completeUsbIdentityCommitment,
                nameof(completeUsbIdentityCommitment));

        _usbIdNumberCommitment =
            CopyRequiredDigest(
                usbIdNumberCommitment,
                nameof(usbIdNumberCommitment));

        _recoveryEmailCommitment =
            CopyRequiredDigest(
                recoveryEmailCommitment,
                nameof(recoveryEmailCommitment));

        _previousIdentityRecordDigest =
            CopyPreviousRecordDigest(
                previousIdentityRecordDigest,
                identityVersion,
                nameof(previousIdentityRecordDigest));

        _identityRecordIntegrityDigest =
            CopyRequiredDigest(
                identityRecordIntegrityDigest,
                nameof(identityRecordIntegrityDigest));

        IdentityVersion = identityVersion;
    }

    /// <summary>
    /// Monotonically increasing protected identity version.
    ///
    /// Version 1 represents initial enrollment.
    /// Every authorized replacement or rotation must increase this value.
    /// </summary>
    public long IdentityVersion { get; }

    /// <summary>
    /// Authenticated-encryption envelope containing the complete canonical
    /// USB identity.
    /// </summary>
    public CryptographicContractEnvelope CompleteUsbIdentityEnvelope { get; }

    /// <summary>
    /// Keyed commitment to the complete canonical USB identity.
    /// </summary>
    public byte[] CompleteUsbIdentityCommitment =>
        (byte[])_completeUsbIdentityCommitment.Clone();

    /// <summary>
    /// Authenticated-encryption envelope containing the canonical USB
    /// identification number.
    /// </summary>
    public CryptographicContractEnvelope UsbIdNumberEnvelope { get; }

    /// <summary>
    /// Keyed commitment to the canonical USB identification number.
    /// </summary>
    public byte[] UsbIdNumberCommitment =>
        (byte[])_usbIdNumberCommitment.Clone();

    /// <summary>
    /// Authenticated-encryption envelope containing the canonical developer
    /// recovery email address.
    /// </summary>
    public CryptographicContractEnvelope RecoveryEmailEnvelope { get; }

    /// <summary>
    /// Keyed commitment to the canonical developer recovery email address.
    /// </summary>
    public byte[] RecoveryEmailCommitment =>
        (byte[])_recoveryEmailCommitment.Clone();

    /// <summary>
    /// VeraCrypt USB custody descriptor to which this protected identity
    /// record is cryptographically associated.
    /// </summary>
    public VeraCryptUsbKeyCustodyDescriptor RequiredUsbCustody { get; }

    /// <summary>
    /// Digest of the immediately preceding protected developer identity.
    ///
    /// This value is empty only for identity version 1.
    /// </summary>
    public byte[] PreviousIdentityRecordDigest =>
        (byte[])_previousIdentityRecordDigest.Clone();

    /// <summary>
    /// Integrity digest covering the canonical serialized representation of
    /// this protected developer identity and all required bindings.
    /// </summary>
    public byte[] IdentityRecordIntegrityDigest =>
        (byte[])_identityRecordIntegrityDigest.Clone();

    private static byte[] CopyRequiredDigest(
        byte[] value,
        string parameterName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (value.Length != CryptographicDigestLength)
        {
            throw new ArgumentException(
                "Cryptographic digest or commitment must be exactly 32 bytes.",
                parameterName);
        }

        return (byte[])value.Clone();
    }

    private static byte[] CopyPreviousRecordDigest(
        byte[] value,
        long identityVersion,
        string parameterName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (identityVersion == 1)
        {
            if (value.Length != 0)
            {
                throw new ArgumentException(
                    "Initial protected identity must not reference a previous identity record.",
                    parameterName);
            }

            return Array.Empty<byte>();
        }

        if (value.Length != CryptographicDigestLength)
        {
            throw new ArgumentException(
                "Non-initial protected identity must reference the previous identity record with a 32-byte digest.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}