namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable data envelope representing one user-device
/// proof-of-possession signature.
///
/// This type carries proof data only.
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
/// The signature is proof material only after independent cryptographic
/// verification against the exact enrolled device public key and the exact
/// canonical K6-L challenge bytes.
///
/// The device fingerprint is an identifier and binding value only.
/// It is not authentication proof.
///
/// The envelope intentionally contains no private-key material.
///
/// Private keys remain independently generated, hardware-backed,
/// non-exportable, and device-local.
///
/// Verification and authentication decisions belong to the I-Mortal
/// confidential identity plane and require the applicable attested
/// confidential-computing boundary.
/// </summary>
public sealed record UserDeviceProofOfPossessionSignatureData(
    string ContractVersion,
    string ProtocolId,
    string ChallengeId,
    string AccountIdentity,
    string DeviceFingerprint,
    string PublicKeyAlgorithm,
    string PublicKeyIdentity,
    string SignatureAlgorithm,
    byte[] SignatureBytes)
{
    public const string CurrentContractVersion = "1";

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE/PROOF-OF-POSSESSION/SIGNATURE-DATA/V1";

    public const bool ContainsPrivateKeyMaterial = false;

    public const bool ContainsRawPrivateKeyMaterial = false;

    public const bool ContainsExportablePrivateKeyMaterial = false;

    public const bool ContainsSignatureMaterial = true;

    public const bool SignatureIsAuthenticationDecision = false;

    public const bool SignatureRequiresIndependentVerification = true;

    public const bool CanonicalChallengeVerificationRequired = true;

    public const bool EnrolledPublicKeyVerificationRequired = true;

    public const bool HardwareKeyProofOfPossessionRequired = true;

    public const bool AccountBindingRequired = true;

    public const bool DeviceBindingRequired = true;

    public const bool ChallengeBindingRequired = true;

    public const bool ProtocolBindingRequired = true;

    public const bool PublicKeyAlgorithmBindingRequired = true;

    public const bool PublicKeyIdentityBindingRequired = true;

    public const bool SignatureAlgorithmBindingRequired = true;

    public const bool ExplicitSignatureAlgorithmRequired = true;

    public const bool UnknownSignatureAlgorithmAllowed = false;

    public const bool AlgorithmDowngradeAllowed = false;

    public const bool EmptySignatureAllowed = false;

    public const bool FingerprintIsIdentifier = true;

    public const bool FingerprintIsBindingValue = true;

    public const bool FingerprintIsAuthenticationProof = false;

    public const bool FingerprintAloneMayAuthenticate = false;

    public const bool PrivateKeyMigrationAllowed = false;

    public const bool PrivateKeyTransferAllowed = false;

    public const bool PrivateKeySynchronizationAllowed = false;

    public const bool PerDeviceIndependentKeyRequired = true;

    public const bool PerDeviceIndependentFingerprintRequired = true;

    public const bool FreshChallengeRequired = true;

    public const bool SingleUseChallengeRequired = true;

    public const bool ExpiringChallengeRequired = true;

    public const bool ReplayAcceptanceAllowed = false;

    public const bool ConfidentialIdentityPlaneRequired = true;

    public const bool AttestedServerIdentityRequired = true;

    public const bool TeeProtectedVerificationRequired = true;

    public const bool ConfidentialVmRequiredForVerification = true;

    public const bool IntelTdxPermitted = true;

    public const bool AmdSevSnpPermitted = true;

    public const bool AttestationRequiredBeforeVerification = true;

    public const bool FailIfAttestationUnavailable = true;

    public const bool FailIfAttestationInvalid = true;

    public const bool GrantsDeveloperSourceAccess = false;

    public const bool GrantsDeveloperUsbAuthority = false;

    public const bool GrantsSourceMutationAuthority = false;

    public const bool GrantsProductionAuthorization = false;

    public const bool PerformsSigning = false;

    public const bool PerformsSignatureVerification = false;

    public const bool PerformsAuthentication = false;

    public const bool PerformsRegistration = false;

    public const bool PerformsDeviceEnrollment = false;

    public const bool PerformsDeviceRevocation = false;

    public const bool PerformsKeyAccess = false;

    public const bool PerformsHardwareAccess = false;

    public const bool FailOpenAllowed = false;

    public const bool DefaultAuthenticationDecision = false;

    public const bool DefaultAuthorizationDecision = false;
}