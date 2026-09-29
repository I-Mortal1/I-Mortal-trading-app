namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Contract defining the explicit signature-algorithm allowlist for
/// I-Mortal user-device proof-of-possession authentication.
///
/// This type is declarative only.
///
/// It performs no:
/// - signing,
/// - signature verification,
/// - authentication,
/// - login authorization,
/// - registration,
/// - device enrollment,
/// - device revocation,
/// - challenge generation,
/// - challenge consumption,
/// - replay-state access,
/// - key generation,
/// - key provisioning,
/// - key unwrap,
/// - private-key access,
/// - private-key export,
/// - private-key transfer,
/// - private-key synchronization,
/// - TPM access,
/// - Secure Enclave access,
/// - Android Keystore access,
/// - Linux TPM access,
/// - network I/O,
/// - developer USB access,
/// - source mutation,
/// - TEE activation,
/// - attestation activation,
/// - production authorization.
///
/// Unknown algorithms are rejected.
///
/// Algorithm selection must be explicit and must match the enrolled
/// device public-key algorithm.
///
/// The device private key remains hardware-backed, non-exportable,
/// device-local, and outside the validator.
///
/// Runtime cryptographic verification is a separate future implementation
/// and must execute only after the required I-Mortal confidential-compute,
/// attestation, approved-workload, and approved-measurement gates succeed.
/// </summary>
public static class UserDeviceProofOfPossessionSignatureAlgorithmAllowlistContract
{
    public const string ContractVersion = "1";

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE/PROOF-OF-POSSESSION/SIGNATURE-ALGORITHM-ALLOWLIST/V1";

    /*
     * Canonical algorithm identifiers.
     *
     * These identifiers are protocol values. They must be compared exactly.
     * Aliases, implicit defaults, case folding, and heuristic substitution
     * are forbidden.
     */

    public const string EcdsaP256Sha256P1363 =
        "ECDSA-P256-SHA256-P1363";

    /*
     * Version-1 allowlist.
     *
     * Exactly one signature suite is admitted by this contract.
     *
     * Additional algorithms require a future reviewed contract revision.
     */

    public static readonly string[] AllowedSignatureAlgorithms =
    [
        EcdsaP256Sha256P1363
    ];

    /*
     * Algorithm semantics.
     */

    public const string EcdsaP256Sha256P1363PublicKeyAlgorithm =
        "EC-P256";

    public const string EcdsaP256Sha256P1363SignaturePrimitive =
        "ECDSA";

    public const string EcdsaP256Sha256P1363Curve =
        "P-256";

    public const string EcdsaP256Sha256P1363Hash =
        "SHA-256";

    public const string EcdsaP256Sha256P1363SignatureEncoding =
        "IEEE-P1363-FIXED-FIELD-CONCATENATION";

    public const int EcdsaP256Sha256P1363SignatureLengthBytes = 64;

    /*
     * Fail-closed algorithm policy.
     */

    public const bool ExplicitAlgorithmIdentifierRequired = true;

    public const bool AlgorithmAllowlistRequired = true;

    public const bool UnknownAlgorithmAllowed = false;

    public const bool ImplicitAlgorithmSelectionAllowed = false;

    public const bool AlgorithmAliasAllowed = false;

    public const bool CaseInsensitiveAlgorithmMatchingAllowed = false;

    public const bool AlgorithmDowngradeAllowed = false;

    public const bool AlgorithmSubstitutionAllowed = false;

    public const bool AlgorithmNegotiationFallbackAllowed = false;

    public const bool MultipleAlgorithmsAllowedForSingleSignature = false;

    public const bool PublicKeyAlgorithmMatchRequired = true;

    public const bool SignatureAlgorithmMatchRequired = true;

    public const bool EnrolledPublicKeyAlgorithmMatchRequired = true;

    /*
     * Signature representation.
     */

    public const bool CanonicalSignatureEncodingRequired = true;

    public const bool AmbiguousSignatureEncodingAllowed = false;

    public const bool DerSignatureEncodingAllowedForEcdsaP256Sha256 = false;

    public const bool P1363FixedFieldEncodingRequiredForEcdsaP256Sha256 = true;

    public const bool ExactSignatureLengthRequired = true;

    /*
     * Key custody.
     */

    public const bool HardwareBackedDevicePrivateKeyRequired = true;

    public const bool NonExportableDevicePrivateKeyRequired = true;

    public const bool DeviceLocalPrivateKeyRequired = true;

    public const bool PrivateKeyMayBeSuppliedToValidator = false;

    public const bool PrivateKeyExportAllowed = false;

    public const bool PrivateKeyTransferAllowed = false;

    public const bool PrivateKeySynchronizationAllowed = false;

    public const bool PublicKeyOnlyVerificationRequired = true;

    /*
     * Confidential-compute boundary.
     */

    public const bool ConfidentialIdentityPlaneRequired = true;

    public const bool TeeRequired = true;

    public const bool AttestationRequired = true;

    public const bool ApprovedWorkloadIdentityRequired = true;

    public const bool ApprovedMeasurementRequired = true;

    public const bool FailIfTeeUnavailable = true;

    public const bool FailIfAttestationInvalid = true;

    public const bool FailIfWorkloadUnapproved = true;

    public const bool FailIfMeasurementUnapproved = true;

    /*
     * Execution boundary.
     *
     * K6-S is contract-only.
     */

    public const bool PerformsSigning = false;

    public const bool PerformsSignatureVerification = false;

    public const bool PerformsAuthentication = false;

    public const bool PerformsLoginAuthorization = false;

    public const bool PerformsRegistration = false;

    public const bool PerformsDeviceEnrollment = false;

    public const bool PerformsDeviceRevocation = false;

    public const bool PerformsChallengeGeneration = false;

    public const bool PerformsChallengeConsumption = false;

    public const bool PerformsReplayStateRead = false;

    public const bool PerformsReplayStateMutation = false;

    public const bool PerformsKeyGeneration = false;

    public const bool PerformsKeyProvisioning = false;

    public const bool PerformsKeyUnwrap = false;

    public const bool PerformsPrivateKeyAccess = false;

    public const bool PerformsPrivateKeyExport = false;

    public const bool PerformsPrivateKeyTransfer = false;

    public const bool PerformsPrivateKeySynchronization = false;

    public const bool PerformsTpmAccess = false;

    public const bool PerformsSecureEnclaveAccess = false;

    public const bool PerformsAndroidKeystoreAccess = false;

    public const bool PerformsLinuxTpmAccess = false;

    public const bool PerformsNetworkIo = false;

    public const bool PerformsDeveloperUsbAccess = false;

    public const bool PerformsSourceMutation = false;

    public const bool ActivatesTee = false;

    public const bool ActivatesAttestation = false;

    public const bool GrantsDeveloperSourceAccess = false;

    public const bool GrantsDeveloperUsbAuthority = false;

    public const bool GrantsSourceMutationAuthority = false;

    public const bool GrantsProductionAuthorization = false;

    /*
     * Fail-closed defaults.
     */

    public const bool DefaultAlgorithmDecision = false;

    public const bool DefaultValidationDecision = false;

    public const bool DefaultAuthenticationDecision = false;

    public const bool DefaultAuthorizationDecision = false;

    public const bool FailOpenAllowed = false;
}