using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Contract-only definition of the canonical input model for an I-MORTAL
/// ordinary-user device cryptographic fingerprint.
///
/// This type performs no hashing, signing, authentication, authorization,
/// enrollment, QR operation, hardware access, key access, provider access,
/// network access, developer USB access, source access, source mutation,
/// TEE activation, attestation, or production authorization.
///
/// The fingerprint is identification and binding data only. It is not a
/// password, bearer credential, private key, authentication token, or
/// authorization decision.
///
/// Authentication must be established independently using a fresh,
/// single-use, expiring challenge and proof-of-possession by the corresponding
/// device-bound hardware-protected private key.
///
/// Canonicalization is deliberately explicit and versioned. Implementations
/// created later must serialize the fields below in the exact prescribed
/// order and encoding before a fingerprint digest is calculated.
/// </summary>
public static class UserDeviceFingerprintCanonicalizationBoundary
{
    public const int ContractVersion = 1;

    public const int CanonicalSchemaVersion = 1;

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE-FINGERPRINT/V1";

    /*
     * Canonical field order:
     *
     *   1. DomainSeparator
     *   2. CanonicalSchemaVersion
     *   3. AccountIdentityBinding
     *   4. PublicKeyAlgorithm
     *   5. CanonicalPublicKey
     *   6. PlatformClass
     *   7. ProviderClass
     *   8. KeyPurpose
     *
     * No private-key bytes may appear in the canonical input.
     *
     * No raw OS machine identifier, hardware serial number, IMEI,
     * MAC address, TPM serial number, developer identity material,
     * developer VeraCrypt USB identity, or mutable display name may
     * be used as the device fingerprint.
     */

    public const int DomainSeparatorFieldOrder = 1;

    public const int CanonicalSchemaVersionFieldOrder = 2;

    public const int AccountIdentityBindingFieldOrder = 3;

    public const int PublicKeyAlgorithmFieldOrder = 4;

    public const int CanonicalPublicKeyFieldOrder = 5;

    public const int PlatformClassFieldOrder = 6;

    public const int ProviderClassFieldOrder = 7;

    public const int KeyPurposeFieldOrder = 8;

    /*
     * Canonical encoding requirements.
     */

    public const bool ExplicitBinaryEncodingRequired = true;

    public const bool JsonCanonicalizationAllowed = false;

    public const bool ReflectionBasedSerializationAllowed = false;

    public const bool CultureSensitiveSerializationAllowed = false;

    public const bool PlatformNativeEndianEncodingAllowed = false;

    public const bool IntegerEncodingBigEndianRequired = true;

    public const bool StringEncodingUtf8Required = true;

    public const bool LengthPrefixRequiredForVariableLengthFields = true;

    public const bool NullCanonicalFieldsAllowed = false;

    public const bool EmptyCanonicalFieldsAllowed = false;

    /*
     * Identity binding requirements.
     */

    public const bool AccountIdentityBindingRequired = true;

    public const bool PublicKeyAlgorithmBindingRequired = true;

    public const bool CanonicalPublicKeyBindingRequired = true;

    public const bool PlatformClassBindingRequired = true;

    public const bool ProviderClassBindingRequired = true;

    public const bool KeyPurposeBindingRequired = true;

    public const bool DomainSeparationRequired = true;

    public const bool SchemaVersionBindingRequired = true;

    /*
     * Each enrolled installation/device has its own cryptographic key.
     *
     * The private key remains local to that device and is expected to be
     * hardware-backed and non-exportable under the platform custody layer.
     */

    public const bool OneAccountMayHaveMultipleDeviceFingerprints = true;

    public const bool IndependentPerDeviceKeyRequired = true;

    public const bool HardwareBackedPrivateKeyRequired = true;

    public const bool NonExportablePrivateKeyRequired = true;

    public const bool PrivateKeyMustRemainOnOriginatingDevice = true;

    public const bool PrivateKeyTransferBetweenDevicesAllowed = false;

    public const bool PrivateKeySynchronizationBetweenDevicesAllowed = false;

    public const bool PrivateKeyDownloadAllowed = false;

    public const bool RawPrivateKeyInCanonicalInputAllowed = false;

    /*
     * Fingerprint semantics.
     */

    public const bool FingerprintDerivedFromCanonicalBytesRequired = true;

    public const bool FingerprintIsPrivateKey = false;

    public const bool FingerprintIsPassword = false;

    public const bool FingerprintIsBearerCredential = false;

    public const bool FingerprintAloneAuthenticates = false;

    public const bool FingerprintAloneAuthorizes = false;

    public const bool FingerprintIdentificationAndBindingOnly = true;

    /*
     * Login/authentication boundary.
     */

    public const bool FreshChallengeRequiredForAuthentication = true;

    public const bool DeviceKeyProofOfPossessionRequiredForAuthentication =
        true;

    public const bool AuthenticationChallengeSingleUseRequired = true;

    public const bool AuthenticationChallengeExpirationRequired = true;

    /*
     * Forbidden raw device identifiers.
     */

    public const bool RawOsMachineIdAllowedAsFingerprint = false;

    public const bool HardwareSerialAllowedAsFingerprint = false;

    public const bool ImeiAllowedAsFingerprint = false;

    public const bool MacAddressAllowedAsFingerprint = false;

    public const bool TpmSerialAllowedAsFingerprint = false;

    /*
     * Developer/user authority separation.
     */

    public const bool UserDeviceFingerprintGrantsDeveloperIdentity = false;

    public const bool UserDeviceFingerprintGrantsDeveloperUsbAccess = false;

    public const bool UserDeviceFingerprintReplacesDeveloperUsb = false;

    public const bool UserDeviceFingerprintGrantsSourceAccess = false;

    public const bool UserDeviceFingerprintGrantsSourceMutation = false;

    public const bool UserDeviceFingerprintGrantsSigningAuthority = false;

    public const bool UserDeviceFingerprintGrantsTeeAuthority = false;

    public const bool UserDeviceFingerprintGrantsProductionAuthority = false;

    /*
     * Platform custody targets.
     *
     * These strings identify architecture classes only.
     * They do not invoke platform APIs.
     */

    public const string WindowsCustodyTarget =
        "TPM_BACKED_APPROVED_PROVIDER";

    public const string AppleCustodyTarget =
        "APPROVED_SECURE_HARDWARE_KEY_PROVIDER";

    public const string AndroidCustodyTarget =
        "HARDWARE_BACKED_KEYSTORE_OR_STRONGBOX_WHERE_AVAILABLE";

    public const string LinuxCustodyTarget =
        "TPM_OR_APPROVED_HARDWARE_SECURITY_PROVIDER";

    /*
     * Fail-closed architectural boundary.
     */

    public const bool FailOpenAllowed = false;
}