namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Canonical implementation contract for the I-Mortal approved-workload gate.
///
/// This type defines security invariants only.
///
/// It performs no authorization, authentication, cryptographic operation,
/// USB access, VeraCrypt access, email access, signing, attestation
/// activation, TEE activation, registration, production promotion,
/// or source mutation.
///
/// DEVELOPER VERIFICATION MODES
/// ============================
///
/// Developer source-custody verification has two distinct modes.
///
/// Normal mode:
///
///     USB available
///         -> canonical USB / VeraCrypt developer verification
///
/// Recovery mode:
///
///     canonical USB unavailable
///         -> independently pre-registered email recovery verification
///
/// Email recovery is not part of normal USB verification.
///
/// USB verification and email recovery verification are not simultaneously
/// required for one developer verification transaction.
///
/// The email recovery path is permitted only for the explicitly defined
/// USB-unavailable recovery mode.
///
/// Successful completion of either developer verification mode establishes
/// only the developer verification prerequisite represented by that mode.
///
/// Neither mode independently establishes:
/// - project-integrity authorization,
/// - approved-workload authorization,
/// - TEE attestation,
/// - production authorization,
/// - source-mutation authority,
/// - I-Mortal Security Umbrella root authority.
///
/// DOWNSTREAM AND-ONLY CHAIN
/// =========================
///
/// A successful developer verification mode must still traverse the
/// independent downstream security gates:
///
///     successful developer verification
///         AND project integrity
///         AND approved workload
///         AND TEE attestation
///         AND final strict source-mutation authority
///
/// Approved-workload authority itself must be derived from independently
/// trusted workload evidence.
///
/// Caller-asserted workload approval is forbidden.
///
/// Project-integrity validation remains an independent prerequisite.
/// Approved-workload validation must not weaken, replace, bypass, or infer
/// satisfaction of project integrity.
///
/// A successful approved-workload decision grants only satisfaction of the
/// approved-workload prerequisite.
///
/// All required downstream conditions are AND-only.
///
/// Unknown, malformed, missing, stale, inconsistent, exceptional, or
/// indeterminate state must deny.
/// </summary>
public static class ApprovedWorkloadGateImplementationContract
{
    public const string ContractVersion =
        "R42-P3-C9-D8-A14-C1";

    public const bool ContractOnly = true;

    // ---------------------------------------------------------------
    // Developer verification mode separation
    // ---------------------------------------------------------------

    public const bool NormalUsbDeveloperVerificationSupported = true;

    public const bool UsbUnavailableEmailRecoveryDeveloperVerificationSupported =
        true;

    public const bool EmailRecoveryIsUsbUnavailableFallbackPath = true;

    public const bool EmailRecoveryIsPartOfNormalUsbVerification = false;

    public const bool UsbAndEmailVerificationRequiredSimultaneously = false;

    public const bool DeveloperVerificationModesAreDistinct = true;

    // Email recovery must not silently become a general alternate path.
    public const bool EmailRecoveryAllowedWhenUsbAvailable = false;

    public const bool EmailRecoveryRequiresPreRegisteredIdentity = true;

    public const bool EmailRecoveryMayReplaceUsbRootKey = false;

    public const bool EmailRecoveryMayExportUsbRootKey = false;

    public const bool EmailRecoveryMayReissueUsbRootKey = false;

    // ---------------------------------------------------------------
    // Neither developer-verification path independently satisfies A14
    // ---------------------------------------------------------------

    public const bool DeveloperUsbVerificationAloneMayApproveWorkload = false;

    public const bool
        DeveloperEmailRecoveryVerificationAloneMayApproveWorkload = false;

    // ---------------------------------------------------------------
    // Downstream AND-only requirements
    // ---------------------------------------------------------------

    public const bool ProjectIntegrityRequiredAfterDeveloperVerification = true;

    public const bool ApprovedWorkloadRequiredAfterDeveloperVerification = true;

    public const bool TeeAttestationRequiredAfterDeveloperVerification = true;

    public const bool
        StrictSourceMutationAuthorityRequiredAfterDeveloperVerification = true;

    public const bool DownstreamSecurityGatesAreAndOnly = true;

    // ---------------------------------------------------------------
    // Existing authority boundaries remain independent
    // ---------------------------------------------------------------

    public const bool ProjectIntegrityPrerequisiteRequired = true;

    public const bool ApprovedWorkloadIsIndependentGate = true;

    public const bool TeeAttestationRemainsIndependentGate = true;

    public const bool DeveloperSourceAuthorityRemainsIndependentGate = true;

    public const bool ProductionAuthorizationRemainsIndependentGate = true;

    // ---------------------------------------------------------------
    // Approved workload evidence requirements
    // ---------------------------------------------------------------

    public const bool TrustedWorkloadEvidenceRequired = true;

    public const bool ImmutableRequiredPolicyRequired = true;

    public const bool ExactApprovedWorkloadDigestRequired = true;

    public const bool ProjectIntegrityWorkloadBindingRequired = true;

    public const bool ChallengeBindingRequired = true;

    public const bool EvidenceFreshnessRequired = true;

    // ---------------------------------------------------------------
    // Exact identity semantics
    // ---------------------------------------------------------------

    public const bool ExactDigestComparisonRequired = true;

    public const bool ConstantTimeDigestComparisonRequired = true;

    public const bool PartialDigestMatchingAllowed = false;

    public const bool PrefixMatchingAllowed = false;

    public const bool TruncatedDigestMatchingAllowed = false;

    public const bool CallerAssertedApprovalAllowed = false;

    public const bool CallerSuppliedExpectedDigestAllowed = false;

    // ---------------------------------------------------------------
    // No unrelated state can independently satisfy A14
    // ---------------------------------------------------------------

    public const bool UsbPossessionAloneMayApproveWorkload = false;

    public const bool VeraCryptMountAloneMayApproveWorkload = false;

    public const bool UserDeviceKeyMayApproveWorkload = false;

    public const bool AdministratorStatusMayApproveWorkload = false;

    public const bool ProductionFlagMayApproveWorkload = false;

    public const bool TeeResultAloneMayApproveWorkload = false;

    // ---------------------------------------------------------------
    // No downgrade or fallback
    // ---------------------------------------------------------------

    public const bool SoftwareFallbackAllowed = false;

    public const bool MissingEvidenceFallbackAllowed = false;

    public const bool UnknownWorkloadAllowed = false;

    public const bool StaleEvidenceAllowed = false;

    public const bool MalformedEvidenceAllowed = false;

    public const bool IndeterminateEvidenceAllowed = false;

    public const bool ExceptionMayAuthorize = false;

    public const bool FailOpenAllowed = false;

    // ---------------------------------------------------------------
    // A14 cannot manufacture downstream authority
    // ---------------------------------------------------------------

    public const bool GrantsDeveloperSourceAccess = false;

    public const bool GrantsSourceMutationAuthority = false;

    public const bool GrantsProjectSigningAuthority = false;

    public const bool GrantsProductionAuthorization = false;

    public const bool GrantsUserRuntimeAuthorization = false;

    public const bool GrantsTeeAuthorization = false;

    public const bool GrantsUmbrellaRootAuthorization = false;

    public const bool DefaultAuthorizationDecision = false;
}