namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable, non-authoritative result envelope describing the outcome of
/// proof-of-possession validation predicates.
///
/// This record contains validation-result data only.
///
/// It does not:
/// - verify signatures,
/// - authenticate users,
/// - authorize login,
/// - generate or consume challenges,
/// - read or mutate replay state,
/// - enroll or revoke devices,
/// - access private keys,
/// - access TPM / Secure Enclave / Android Keystore / Linux TPM,
/// - perform network I/O,
/// - activate a TEE,
/// - activate attestation,
/// - grant developer authority,
/// - grant source-mutation authority,
/// - grant production authorization.
///
/// Validation success is not itself an authentication or authorization
/// decision. A separate fail-closed authentication-policy evaluation is
/// required.
///
/// DeviceFingerprint is identification and binding data only.
/// It is not authentication proof.
/// </summary>
public sealed record UserDeviceProofOfPossessionValidationResultData(
    string ContractVersion,
    string ProtocolId,
    string ChallengeId,
    string AccountIdentity,
    string DeviceFingerprint,
    string PublicKeyAlgorithm,
    string PublicKeyIdentity,
    string SignatureAlgorithm,
    bool ContractVersionValid,
    bool ProtocolBindingValid,
    bool ChallengeBindingValid,
    bool AccountBindingValid,
    bool DeviceBindingValid,
    bool PublicKeyAlgorithmBindingValid,
    bool PublicKeyIdentityBindingValid,
    bool SignatureAlgorithmBindingValid,
    bool CanonicalChallengeBindingValid,
    bool EnrolledDeviceValid,
    bool EnrolledDeviceActive,
    bool EnrolledPublicKeyValid,
    bool HardwareBackedKeyRequirementSatisfied,
    bool NonExportableKeyRequirementSatisfied,
    bool SignaturePresent,
    bool SignatureAlgorithmApproved,
    bool SignatureCryptographicallyValid,
    bool ChallengeFresh,
    bool ChallengeNotExpired,
    bool ChallengeSingleUseStateValid,
    bool ReplayStateValid,
    bool AttestationPresent,
    bool AttestationFresh,
    bool AttestationPolicyValid,
    bool ApprovedWorkloadIdentityValid,
    bool ApprovedMeasurementValid,
    bool TeeValidationBoundarySatisfied,
    bool AllMandatoryValidationPredicatesSatisfied)
{
    public const string CurrentContractVersion = "1";

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE/PROOF-OF-POSSESSION/VALIDATION-RESULT/V1";

    public const bool ImmutableResultEnvelope = true;

    public const bool ResultIsNonAuthoritative = true;

    public const bool ResultIsAuthenticationDecision = false;

    public const bool ResultIsLoginAuthorization = false;

    public const bool ResultIsEnrollmentAuthorization = false;

    public const bool ResultIsDeveloperAuthority = false;

    public const bool ResultIsSourceMutationAuthority = false;

    public const bool ResultIsProductionAuthorization = false;

    public const bool FingerprintIsIdentifier = true;

    public const bool FingerprintIsBindingValue = true;

    public const bool FingerprintIsAuthenticationProof = false;

    public const bool HardwareKeyProofOfPossessionRequired = true;

    public const bool AllMandatoryPredicatesRequired = true;

    public const bool PartialValidationAcceptanceAllowed = false;

    public const bool UnknownValidationStateAccepted = false;

    public const bool MissingValidationStateAccepted = false;

    public const bool CryptographicSignatureValidationRequired = true;

    public const bool FreshChallengeRequired = true;

    public const bool UnexpiredChallengeRequired = true;

    public const bool SingleUseChallengeRequired = true;

    public const bool ReplayValidationRequired = true;

    public const bool AccountBindingRequired = true;

    public const bool DeviceBindingRequired = true;

    public const bool PublicKeyBindingRequired = true;

    public const bool SignatureAlgorithmBindingRequired = true;

    public const bool CanonicalChallengeBindingRequired = true;

    public const bool EnrolledDeviceRequired = true;

    public const bool ActiveEnrolledDeviceRequired = true;

    public const bool HardwareBackedKeyRequired = true;

    public const bool NonExportableKeyRequired = true;

    public const bool ConfidentialIdentityPlaneRequired = true;

    public const bool TeeProtectedValidationRequired = true;

    public const bool AttestationRequired = true;

    public const bool AttestationFreshnessRequired = true;

    public const bool AttestationPolicyMatchRequired = true;

    public const bool ApprovedWorkloadIdentityRequired = true;

    public const bool ApprovedMeasurementRequired = true;

    public const bool AdditionalAuthenticationPolicyEvaluationRequired = true;

    public const bool PrivateKeyMigrationAllowed = false;

    public const bool PrivateKeyTransferAllowed = false;

    public const bool PrivateKeySynchronizationAllowed = false;

    public const bool PerformsSignatureVerification = false;

    public const bool PerformsValidation = false;

    public const bool PerformsAuthentication = false;

    public const bool PerformsLogin = false;

    public const bool PerformsRegistration = false;

    public const bool PerformsDeviceEnrollment = false;

    public const bool PerformsDeviceRevocation = false;

    public const bool PerformsChallengeGeneration = false;

    public const bool PerformsChallengeConsumption = false;

    public const bool PerformsReplayStateRead = false;

    public const bool PerformsReplayStateMutation = false;

    public const bool PerformsKeyAccess = false;

    public const bool PerformsHardwareAccess = false;

    public const bool PerformsNetworkAccess = false;

    public const bool PerformsTeeActivation = false;

    public const bool PerformsAttestationActivation = false;

    public const bool GrantsDeveloperSourceAccess = false;

    public const bool GrantsDeveloperUsbAuthority = false;

    public const bool GrantsSourceMutationAuthority = false;

    public const bool GrantsProductionAuthorization = false;

    public const bool FailOpenAllowed = false;

    public const bool DefaultValidationDecision = false;

    public const bool DefaultAuthenticationDecision = false;

    public const bool DefaultAuthorizationDecision = false;
}