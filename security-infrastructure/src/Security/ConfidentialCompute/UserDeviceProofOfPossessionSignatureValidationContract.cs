namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Contract governing validation of a user-device proof-of-possession
/// signature.
///
/// This contract defines mandatory validation predicates only.
/// It performs no cryptographic verification or authentication.
///
/// A future validator must fail closed unless every mandatory predicate
/// succeeds.
///
/// The device fingerprint remains an identifier and binding value only.
/// It is never sufficient authentication proof.
///
/// Successful signature validation alone must not directly grant login,
/// enrollment, developer authority, source mutation authority, or
/// production authorization.
/// </summary>
public static class UserDeviceProofOfPossessionSignatureValidationContract
{
    public const string CurrentContractVersion = "1";

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE/PROOF-OF-POSSESSION/SIGNATURE-VALIDATION/V1";

    public const bool ExactContractVersionRequired = true;

    public const bool ExactProtocolBindingRequired = true;

    public const bool ExactChallengeIdBindingRequired = true;

    public const bool ExactAccountIdentityBindingRequired = true;

    public const bool ExactDeviceFingerprintBindingRequired = true;

    public const bool ExactPublicKeyAlgorithmBindingRequired = true;

    public const bool ExactPublicKeyIdentityBindingRequired = true;

    public const bool ExactSignatureAlgorithmBindingRequired = true;

    public const bool ExactCanonicalChallengeBytesRequired = true;

    public const bool CanonicalChallengeReconstructionRequired = true;

    public const bool EnrolledDeviceRequired = true;

    public const bool EnrolledDeviceActiveStateRequired = true;

    public const bool EnrolledPublicKeyRequired = true;

    public const bool EnrolledPublicKeyIdentityMatchRequired = true;

    public const bool EnrolledPublicKeyAlgorithmMatchRequired = true;

    public const bool HardwareBackedKeyEnrollmentRequired = true;

    public const bool NonExportableKeyEnrollmentRequired = true;

    public const bool SignaturePresentRequired = true;

    public const bool EmptySignatureAllowed = false;

    public const bool ApprovedSignatureAlgorithmRequired = true;

    public const bool UnknownSignatureAlgorithmAllowed = false;

    public const bool AlgorithmDowngradeAllowed = false;

    public const bool CryptographicSignatureVerificationRequired = true;

    public const bool SignatureVerificationAgainstEnrolledPublicKeyRequired = true;

    public const bool SignatureVerificationAgainstCanonicalChallengeRequired = true;

    public const bool FingerprintIsIdentifier = true;

    public const bool FingerprintIsBindingValue = true;

    public const bool FingerprintIsAuthenticationProof = false;

    public const bool FingerprintAloneMayAuthenticate = false;

    public const bool FreshChallengeRequired = true;

    public const bool ChallengeIssuedAtValidationRequired = true;

    public const bool ChallengeExpirationValidationRequired = true;

    public const bool ChallengeMustNotBeExpired = true;

    public const bool SingleUseChallengeRequired = true;

    public const bool ReplayStateValidationRequired = true;

    public const bool PreviouslyConsumedChallengeAllowed = false;

    public const bool ReplayAcceptanceAllowed = false;

    public const bool ChallengeConsumptionRequiredAfterSuccessfulVerification = true;

    public const bool ChallengeConsumptionMustBeAtomic = true;

    public const bool ChallengeConsumptionBeforeCryptographicVerificationAllowed = false;

    public const bool AccountBindingRequired = true;

    public const bool DeviceBindingRequired = true;

    public const bool ChallengeBindingRequired = true;

    public const bool ProtocolBindingRequired = true;

    public const bool PublicKeyBindingRequired = true;

    public const bool SignatureAlgorithmBindingRequired = true;

    public const bool IndependentHardwareKeyProofRequired = true;

    public const bool PrivateKeyMigrationAllowed = false;

    public const bool PrivateKeyTransferAllowed = false;

    public const bool PrivateKeySynchronizationAllowed = false;

    public const bool PerDeviceIndependentKeyRequired = true;

    public const bool PerDeviceIndependentFingerprintRequired = true;

    public const bool ConfidentialIdentityPlaneRequired = true;

    public const bool AttestedServerIdentityRequired = true;

    public const bool TeeProtectedValidationRequired = true;

    public const bool ConfidentialVmRequiredForValidation = true;

    public const bool IntelTdxPermitted = true;

    public const bool AmdSevSnpPermitted = true;

    public const bool AttestationRequiredBeforeValidation = true;

    public const bool AttestationFreshnessRequired = true;

    public const bool AttestationPolicyMatchRequired = true;

    public const bool ApprovedWorkloadIdentityRequired = true;

    public const bool ApprovedMeasurementRequired = true;

    public const bool FailIfAttestationUnavailable = true;

    public const bool FailIfAttestationInvalid = true;

    public const bool FailIfAttestationStale = true;

    public const bool FailIfWorkloadUnapproved = true;

    public const bool SuccessfulValidationIsAuthenticationDecision = false;

    public const bool SuccessfulValidationDirectlyGrantsLogin = false;

    public const bool SuccessfulValidationDirectlyGrantsEnrollment = false;

    public const bool SuccessfulValidationDirectlyGrantsDeveloperAuthority = false;

    public const bool SuccessfulValidationDirectlyGrantsSourceMutationAuthority = false;

    public const bool SuccessfulValidationDirectlyGrantsProductionAuthorization = false;

    public const bool AdditionalAuthenticationPolicyEvaluationRequired = true;

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