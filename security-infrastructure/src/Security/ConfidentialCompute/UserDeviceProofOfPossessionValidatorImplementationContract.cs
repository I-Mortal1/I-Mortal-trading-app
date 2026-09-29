namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Contract for a future implementation of
/// IUserDeviceProofOfPossessionValidator.
///
/// This type defines security invariants only.
///
/// It does not:
/// - verify signatures,
/// - generate challenges,
/// - consume challenges,
/// - read or mutate replay state,
/// - authenticate users,
/// - authorize login,
/// - enroll devices,
/// - revoke devices,
/// - generate keys,
/// - provision keys,
/// - unwrap keys,
/// - access private keys,
/// - export private keys,
/// - transfer private keys,
/// - synchronize private keys,
/// - access a TPM,
/// - access Secure Enclave,
/// - access Android Keystore,
/// - access Linux TPM,
/// - perform network I/O,
/// - activate a TEE,
/// - perform attestation,
/// - authorize production,
/// - grant developer authority,
/// - grant source-mutation authority.
///
/// The future validator must operate only inside the approved I-Mortal
/// confidential identity plane.
///
/// Runtime validation must be protected by the approved confidential
/// computing boundary, including Intel TDX and/or AMD SEV-SNP as
/// applicable to the approved workload.
///
/// Required attestation, approved-workload identity, and approved
/// measurement predicates must already be satisfied before validation
/// can produce a successful result.
///
/// DeviceFingerprint is identification and binding data only.
/// It is not authentication proof.
///
/// Proof of possession requires successful verification using the
/// enrolled device's public key against a signature produced by that
/// device's independently generated, hardware-backed, non-exportable
/// private key.
///
/// The private key must never be supplied to the validator.
///
/// Validation is conjunctive and fail-closed. Every mandatory predicate
/// must be satisfied. Partial validation is forbidden.
///
/// A successful validation result is non-authoritative and does not by
/// itself authenticate the user or authorize login. Separate fail-closed
/// authentication-policy evaluation is required.
///
/// Replay-state mutation and challenge consumption must remain separate
/// state-transition operations and must not be silently performed by a
/// pure validation operation.
///
/// Unknown algorithms, malformed keys, malformed signatures, malformed
/// challenge data, missing state, inconsistent bindings, stale
/// attestation, invalid measurements, unsupported protocol values,
/// internal exceptions, and indeterminate states must fail closed.
/// </summary>
public static class UserDeviceProofOfPossessionValidatorImplementationContract
{
    public const string CurrentContractVersion = "1";

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE/PROOF-OF-POSSESSION/VALIDATOR/IMPLEMENTATION/V1";

    public const bool ContractOnly = true;

    public const bool ValidationExecutionImplemented = false;

    public const bool SignatureVerificationImplemented = false;

    public const bool AuthenticationImplemented = false;

    public const bool LoginAuthorizationImplemented = false;

    public const bool DeviceEnrollmentImplemented = false;

    public const bool DeviceRevocationImplemented = false;

    public const bool ChallengeGenerationImplemented = false;

    public const bool ChallengeConsumptionImplemented = false;

    public const bool ReplayStateReadImplemented = false;

    public const bool ReplayStateMutationImplemented = false;

    public const bool KeyGenerationImplemented = false;

    public const bool KeyProvisioningImplemented = false;

    public const bool KeyUnwrapImplemented = false;

    public const bool PrivateKeyAccessImplemented = false;

    public const bool PrivateKeyExportImplemented = false;

    public const bool PrivateKeyTransferImplemented = false;

    public const bool PrivateKeySynchronizationImplemented = false;

    public const bool TpmAccessImplemented = false;

    public const bool SecureEnclaveAccessImplemented = false;

    public const bool AndroidKeystoreAccessImplemented = false;

    public const bool LinuxTpmAccessImplemented = false;

    public const bool NetworkIoImplemented = false;

    public const bool TeeActivationImplemented = false;

    public const bool AttestationExecutionImplemented = false;

    public const bool ProductionAuthorizationImplemented = false;

    public const bool GrantsDeveloperSourceAccess = false;

    public const bool GrantsDeveloperUsbAuthority = false;

    public const bool GrantsSourceMutationAuthority = false;

    public const bool GrantsProductionAuthorization = false;

    public const bool ConfidentialIdentityPlaneRequired = true;

    public const bool TeeProtectedValidationRequired = true;

    public const bool IntelTdxSupportedBoundaryRequired = true;

    public const bool AmdSevSnpSupportedBoundaryRequired = true;

    public const bool AttestationRequired = true;

    public const bool FreshAttestationRequired = true;

    public const bool AttestationPolicyValidationRequired = true;

    public const bool ApprovedWorkloadIdentityRequired = true;

    public const bool ApprovedMeasurementRequired = true;

    public const bool EnrolledDeviceRequired = true;

    public const bool ActiveDeviceRequired = true;

    public const bool AccountBindingRequired = true;

    public const bool DeviceBindingRequired = true;

    public const bool PurposeBindingRequired = true;

    public const bool ProtocolBindingRequired = true;

    public const bool ChallengeKnownRequired = true;

    public const bool ChallengeFreshRequired = true;

    public const bool ChallengeUnusedRequired = true;

    public const bool ChallengeNotExpiredRequired = true;

    public const bool ReplayStateValidRequired = true;

    public const bool HardwareBackedKeyRequired = true;

    public const bool NonExportablePrivateKeyRequired = true;

    public const bool CanonicalPublicKeyRequired = true;

    public const bool PublicKeyOnlyVerificationRequired = true;

    public const bool PrivateKeyMayBeSuppliedToValidator = false;

    public const bool FingerprintIsIdentificationAndBindingOnly = true;

    public const bool FingerprintIsAuthenticationProof = false;

    public const bool HardwareKeyProofOfPossessionRequired = true;

    public const bool CanonicalChallengeSerializationRequired = true;

    public const bool SignatureAlgorithmAllowlistRequired = true;

    public const bool UnknownSignatureAlgorithmAllowed = false;

    public const bool MalformedPublicKeyAllowed = false;

    public const bool MalformedSignatureAllowed = false;

    public const bool MalformedChallengeAllowed = false;

    public const bool PartialValidationAcceptanceAllowed = false;

    public const bool AllMandatoryPredicatesRequired = true;

    public const bool IndeterminateValidationAllowed = false;

    public const bool ExceptionMeansValidationSuccess = false;

    public const bool ValidationResultIsNonAuthoritative = true;

    public const bool ValidationResultIsAuthenticationDecision = false;

    public const bool ValidationResultIsLoginAuthorization = false;

    public const bool AdditionalAuthenticationPolicyEvaluationRequired = true;

    public const bool ReplayMutationSeparatedFromValidation = true;

    public const bool ChallengeConsumptionSeparatedFromValidation = true;

    public const bool DefaultValidationDecision = false;

    public const bool DefaultAuthenticationDecision = false;

    public const bool DefaultAuthorizationDecision = false;

    public const bool FailOpenAllowed = false;
}