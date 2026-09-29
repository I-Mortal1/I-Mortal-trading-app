namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Architectural contract for user-device proof-of-possession signatures.
///
/// This contract defines security invariants only.
///
/// It performs no:
/// - signing,
/// - signature verification,
/// - challenge generation,
/// - challenge consumption,
/// - authentication,
/// - login authorization,
/// - registration,
/// - device enrollment,
/// - device revocation,
/// - QR generation,
/// - QR scanning,
/// - network I/O,
/// - key generation,
/// - key provisioning,
/// - key unwrap,
/// - raw private-key access,
/// - private-key export,
/// - private-key transfer,
/// - private-key synchronization,
/// - TPM access,
/// - Secure Enclave access,
/// - Android Keystore access,
/// - Linux TPM access,
/// - developer USB access,
/// - source mutation,
/// - TEE activation,
/// - production authorization.
///
/// Device fingerprints are identifiers and cryptographic binding values only.
/// They are never authentication proof.
///
/// Authentication requires proof of possession of the enrolled device's
/// hardware-backed, non-exportable private key.
///
/// Every proof-of-possession signature must bind to the exact canonical
/// K6-L challenge bytes.
///
/// The signing operation belongs inside the device's platform-protected
/// cryptographic boundary.
///
/// Server-side verification and authentication decisions belong inside the
/// I-Mortal confidential identity plane protected by an attested confidential
/// computing boundary.
///
/// Private keys must never migrate between devices.
///
/// A newly enrolled device receives its own hardware-backed, non-exportable
/// key pair and its own device fingerprint.
///
/// Cross-device account access therefore proves possession of an independently
/// enrolled device key; it never copies the original device private key.
/// </summary>
public static class UserDeviceProofOfPossessionSignatureContract
{
    public const string CurrentContractVersion = "1";

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE/PROOF-OF-POSSESSION/SIGNATURE/V1";

    /*
     * Signature input.
     */

    public const bool CanonicalChallengeBytesRequired = true;

    public const bool ExactK6LCanonicalSerializationRequired = true;

    public const bool SignatureInputDomainSeparated = true;

    public const bool ChallengeIdBindingRequired = true;

    public const bool ChallengeNonceBindingRequired = true;

    public const bool AccountBindingRequired = true;

    public const bool DeviceFingerprintBindingRequired = true;

    public const bool AuthenticationPurposeBindingRequired = true;

    public const bool ProtocolBindingRequired = true;

    public const bool IssuedAtBindingRequired = true;

    public const bool ExpiresAtBindingRequired = true;

    /*
     * Key custody.
     */

    public const bool HardwareBackedPrivateKeyRequired = true;

    public const bool NonExportablePrivateKeyRequired = true;

    public const bool PrivateKeyMigrationAllowed = false;

    public const bool PrivateKeyTransferAllowed = false;

    public const bool PrivateKeySynchronizationAllowed = false;

    public const bool RawPrivateKeyExposureAllowed = false;

    public const bool PerDeviceKeyPairRequired = true;

    public const bool PerDeviceFingerprintRequired = true;

    /*
     * Platform custody.
     *
     * Concrete platform adapters may use the strongest appropriate
     * hardware-backed facility available to that platform.
     */

    public const bool WindowsTpmCustodySupported = true;

    public const bool AppleSecureEnclaveCustodySupported = true;

    public const bool AndroidHardwareBackedKeystoreSupported = true;

    public const bool LinuxTpmCustodySupported = true;

    /*
     * Fingerprint semantics.
     */

    public const bool FingerprintIsIdentifier = true;

    public const bool FingerprintIsBindingValue = true;

    public const bool FingerprintIsAuthenticationProof = false;

    public const bool FingerprintAloneMayAuthenticate = false;

    /*
     * Proof-of-possession semantics.
     */

    public const bool FreshChallengeRequired = true;

    public const bool SingleUseChallengeRequired = true;

    public const bool ExpiringChallengeRequired = true;

    public const bool ReplayAcceptanceAllowed = false;

    public const bool HardwareKeyProofOfPossessionRequired = true;

    public const bool SignatureRequiredForDeviceAuthentication = true;

    public const bool SignatureSubstitutionAllowed = false;

    public const bool ChallengeSubstitutionAllowed = false;

    public const bool DeviceSubstitutionAllowed = false;

    public const bool AccountSubstitutionAllowed = false;

    public const bool PurposeSubstitutionAllowed = false;

    public const bool ProtocolSubstitutionAllowed = false;

    /*
     * Signature algorithm contract.
     *
     * Algorithm selection must be explicit. No implicit/default algorithm
     * interpretation is permitted.
     *
     * Concrete algorithm allowlists are intentionally not activated by this
     * contract-only stage.
     */

    public const bool ExplicitSignatureAlgorithmIdentifierRequired = true;

    public const bool ImplicitSignatureAlgorithmAllowed = false;

    public const bool AlgorithmDowngradeAllowed = false;

    public const bool UnknownSignatureAlgorithmAllowed = false;

    public const bool SignatureEncodingMustBeCanonical = true;

    public const bool AmbiguousSignatureEncodingAllowed = false;

    /*
     * Verification obligations.
     */

    public const bool EnrolledPublicKeyRequiredForVerification = true;

    public const bool ExactDevicePublicKeyBindingRequired = true;

    public const bool ExactDeviceFingerprintMatchRequired = true;

    public const bool ExactAccountMatchRequired = true;

    public const bool ExactPurposeMatchRequired = true;

    public const bool ExactProtocolMatchRequired = true;

    public const bool ChallengeFreshnessVerificationRequired = true;

    public const bool ChallengeExpirationVerificationRequired = true;

    public const bool ChallengeSingleUseVerificationRequired = true;

    public const bool ReplayStateVerificationRequired = true;

    public const bool CryptographicSignatureVerificationRequired = true;

    /*
     * Confidential-computing boundary.
     */

    public const bool ConfidentialIdentityPlaneRequired = true;

    public const bool AttestedServerIdentityRequired = true;

    public const bool TeeProtectedAuthenticationProcessingRequired = true;

    public const bool ConfidentialVmRequiredForServerIdentityPlane = true;

    public const bool IntelTdxPermitted = true;

    public const bool AmdSevSnpPermitted = true;

    public const bool AttestationRequiredBeforeSensitiveIdentityProcessing =
        true;

    public const bool FailIfAttestationUnavailable = true;

    public const bool FailIfAttestationInvalid = true;

    /*
     * Cross-device enrollment model.
     */

    public const bool OriginalDevicePrivateKeyTransferRequired = false;

    public const bool OriginalDevicePrivateKeyTransferForbidden = true;

    public const bool NewlyEnrolledDeviceGeneratesIndependentKeyPair = true;

    public const bool NewlyEnrolledDeviceUsesIndependentFingerprint = true;

    public const bool ExistingTrustedDeviceMayAuthorizeEnrollmentChallenge =
        true;

    public const bool EnrollmentAuthorizationTransfersPrivateKey = false;

    /*
     * Authority separation.
     */

    public const bool GrantsDeveloperSourceAccess = false;

    public const bool GrantsDeveloperUsbAuthority = false;

    public const bool GrantsSourceMutationAuthority = false;

    public const bool GrantsProductionAuthorization = false;

    public const bool PerformsRegistration = false;

    public const bool PerformsAuthentication = false;

    public const bool PerformsSigning = false;

    public const bool PerformsSignatureVerification = false;

    public const bool PerformsKeyAccess = false;

    public const bool PerformsHardwareAccess = false;

    /*
     * Fail-closed defaults.
     */

    public const bool FailOpenAllowed = false;

    public const bool DefaultAuthenticationDecision = false;

    public const bool DefaultAuthorizationDecision = false;
}