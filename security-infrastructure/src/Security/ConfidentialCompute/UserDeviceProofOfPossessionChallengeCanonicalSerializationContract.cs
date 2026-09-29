namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Architectural contract for canonical serialization of an I-Mortal
/// user-device proof-of-possession challenge.
///
/// This contract defines only the deterministic byte-level representation
/// that a later implementation must produce before the challenge is signed
/// or otherwise cryptographically bound.
///
/// This contract does not:
/// - generate challenges,
/// - generate or access keys,
/// - sign challenges,
/// - verify signatures,
/// - authenticate users,
/// - enroll or revoke devices,
/// - access TPM / Secure Enclave / Android Keystore / Linux TPM,
/// - perform network communication,
/// - activate TEE or attestation authority,
/// - grant developer USB access,
/// - grant source access or source mutation authority,
/// - grant production authorization.
///
/// Serialization requirements:
///
/// 1. The encoding is deterministic and canonical.
/// 2. The encoding is explicitly binary.
/// 3. Multi-byte integer values use big-endian network byte order.
/// 4. Text values use strict UTF-8 without a BOM.
/// 5. Invalid Unicode is rejected.
/// 6. Text values must already be Unicode NFC; non-NFC input is rejected.
/// 7. Variable-length fields are length-prefixed.
/// 8. Null and empty required values are rejected.
/// 9. Field ordering is fixed and immutable for this contract version.
/// 10. The serialized representation is domain-separated.
/// 11. The serialized representation binds the challenge to:
///     - contract version,
///     - protocol identifier,
///     - challenge identifier,
///     - challenge nonce,
///     - account identity,
///     - I-Mortal device fingerprint,
///     - authentication purpose,
///     - issued-at time,
///     - expiration time.
/// 12. The fingerprint is identification/binding data only and is never
///     accepted as proof of authentication.
/// 13. Authentication requires fresh hardware-key proof-of-possession under
///     the independently defined proof-of-possession protocol.
/// 14. Challenge freshness, expiration, single-use enforcement and replay
///     rejection remain mandatory protocol requirements.
/// 15. Serialization failure must fail closed.
/// 16. No private-key material may appear in the serialized challenge.
/// 17. Per-device private keys remain hardware-backed, non-exportable and
///     non-migratable.
/// 18. Registration, login, enrollment and proof-of-possession processing
///     remain inside the attested I-Mortal confidential identity plane.
/// </summary>
public static class UserDeviceProofOfPossessionChallengeCanonicalSerializationContract
{
    public const string ContractVersion = "1";

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE-PROOF-OF-POSSESSION/CHALLENGE/CANONICAL/V1";

    public const string EncodingModel =
        "EXPLICIT_BINARY";

    public const string IntegerByteOrder =
        "BIG_ENDIAN_NETWORK_ORDER";

    public const string TextEncoding =
        "STRICT_UTF8_NO_BOM";

    public const string UnicodeNormalization =
        "NFC";

    public const string VariableLengthFieldEncoding =
        "UINT32_BIG_ENDIAN_LENGTH_PREFIX";

    public const string TimestampEncoding =
        "INT64_BIG_ENDIAN_UNIX_TIME_MILLISECONDS";

    public const string FieldOrder =
        "DOMAIN_SEPARATOR|" +
        "CONTRACT_VERSION|" +
        "PROTOCOL_ID|" +
        "CHALLENGE_ID|" +
        "CHALLENGE_NONCE|" +
        "ACCOUNT_IDENTITY|" +
        "DEVICE_FINGERPRINT|" +
        "AUTHENTICATION_PURPOSE|" +
        "ISSUED_AT|" +
        "EXPIRES_AT";

    public const bool DeterministicSerializationRequired = true;

    public const bool ExplicitBinaryEncodingRequired = true;

    public const bool BigEndianRequired = true;

    public const bool StrictUtf8Required = true;

    public const bool Utf8BomForbidden = true;

    public const bool InvalidUnicodeRejected = true;

    public const bool UnicodeNfcRequired = true;

    public const bool LengthPrefixRequired = true;

    public const bool FixedFieldOrderRequired = true;

    public const bool DomainSeparationRequired = true;

    public const bool ContractVersionBindingRequired = true;

    public const bool ProtocolBindingRequired = true;

    public const bool ChallengeIdBindingRequired = true;

    public const bool ChallengeNonceBindingRequired = true;

    public const bool AccountBindingRequired = true;

    public const bool DeviceFingerprintBindingRequired = true;

    public const bool AuthenticationPurposeBindingRequired = true;

    public const bool IssuedAtBindingRequired = true;

    public const bool ExpiresAtBindingRequired = true;

    public const bool NullRequiredValuesRejected = true;

    public const bool EmptyRequiredValuesRejected = true;

    public const bool PrivateKeyMaterialForbidden = true;

    public const bool FingerprintIsAuthenticationProof = false;

    public const bool HardwareKeyProofOfPossessionRequired = true;

    public const bool FreshChallengeRequired = true;

    public const bool SingleUseRequired = true;

    public const bool ExpirationRequired = true;

    public const bool ReplayAcceptanceAllowed = false;

    public const bool PrivateKeyMigrationAllowed = false;

    public const bool ConfidentialIdentityPlaneRequired = true;

    public const bool AttestedServerIdentityRequired = true;

    public const bool DeveloperSourceAccessGranted = false;

    public const bool DeveloperUsbAuthorityGranted = false;

    public const bool SourceMutationAuthorityGranted = false;

    public const bool ProductionAuthorizationGranted = false;

    public const bool FailOpenAllowed = false;

    public const string DefaultDecision = "DENY";
}