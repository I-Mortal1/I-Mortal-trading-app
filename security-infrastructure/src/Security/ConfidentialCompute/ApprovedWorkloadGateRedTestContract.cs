namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Mandatory negative-test contract for the I-Mortal approved-workload gate.
///
/// This type contains test requirements only.
/// It performs no authorization and grants no authority.
///
/// Before an approved-workload implementation may be considered for
/// registration, every denial requirement represented here must be proven.
///
/// Developer verification consists of two distinct modes:
///
/// NORMAL:
///     canonical USB available -> USB/VeraCrypt verification.
///
/// RECOVERY:
///     canonical USB unavailable -> pre-registered email verification.
///
/// Email recovery must not be invoked merely because normal USB verification
/// failed while the canonical USB remains available.
///
/// USB and email verification are not simultaneous requirements for one
/// developer-verification transaction.
///
/// Successful completion of either developer-verification mode is not
/// approved-workload authorization.
///
/// Approved workload remains an independent downstream AND-only gate.
/// </summary>
public static class ApprovedWorkloadGateRedTestContract
{
    public const string ContractVersion =
        "R42-P3-C9-D8-A14-C2";

    public const bool ContractOnly = true;

    // ---------------------------------------------------------------
    // Baseline fail-closed cases
    // ---------------------------------------------------------------

    public const bool MissingEvidenceMustDeny = true;

    public const bool NullEvidenceMustDeny = true;

    public const bool MalformedEvidenceMustDeny = true;

    public const bool UnknownEvidenceMustDeny = true;

    public const bool IndeterminateEvidenceMustDeny = true;

    public const bool StaleEvidenceMustDeny = true;

    public const bool DependencyExceptionMustDeny = true;

    public const bool VerificationExceptionMustDeny = true;

    // ---------------------------------------------------------------
    // Approved-workload digest cases
    // ---------------------------------------------------------------

    public const bool MissingApprovedWorkloadDigestMustDeny = true;

    public const bool EmptyApprovedWorkloadDigestMustDeny = true;

    public const bool MalformedApprovedWorkloadDigestMustDeny = true;

    public const bool WrongLengthApprovedWorkloadDigestMustDeny = true;

    public const bool MismatchedApprovedWorkloadDigestMustDeny = true;

    public const bool PartialApprovedWorkloadDigestMustDeny = true;

    public const bool PrefixApprovedWorkloadDigestMustDeny = true;

    public const bool TruncatedApprovedWorkloadDigestMustDeny = true;

    public const bool CallerSuppliedExpectedDigestMustDeny = true;

    public const bool CallerAssertedWorkloadApprovalMustDeny = true;

    // ---------------------------------------------------------------
    // Project-integrity binding
    // ---------------------------------------------------------------

    public const bool ProjectIntegrityNotValidatedMustDeny = true;

    public const bool ProjectIntegrityDeniedMustDeny = true;

    public const bool ProjectIntegrityWorkloadMismatchMustDeny = true;

    public const bool MissingChallengeBindingMustDeny = true;

    public const bool InvalidChallengeBindingMustDeny = true;

    public const bool ChallengeWorkloadMismatchMustDeny = true;

    // ---------------------------------------------------------------
    // Normal USB developer-verification mode
    // ---------------------------------------------------------------

    public const bool UsbPossessionAloneMustNotApproveWorkload = true;

    public const bool VeraCryptMountAloneMustNotApproveWorkload = true;

    public const bool UsbRootKeyPossessionAloneMustNotApproveWorkload = true;

    public const bool UsbProofOfPossessionAloneMustNotApproveWorkload = true;

    public const bool
        ExactVeraCryptBackingSourceAloneMustNotApproveWorkload = true;

    public const bool
        SuccessfulNormalUsbDeveloperVerificationAloneMustNotApproveWorkload =
            true;

    // ---------------------------------------------------------------
    // USB-unavailable pre-registered email recovery mode
    // ---------------------------------------------------------------

    public const bool
        EmailRecoveryWhenCanonicalUsbAvailableMustDeny = true;

    public const bool
        UnregisteredEmailRecoveryIdentityMustDeny = true;

    public const bool
        WrongPreRegisteredEmailIdentityMustDeny = true;

    public const bool
        FailedEmailRecoveryVerificationMustDeny = true;

    public const bool
        EmailRecoveryAloneMustNotApproveWorkload = true;

    public const bool
        SuccessfulUsbUnavailableEmailRecoveryAloneMustNotApproveWorkload =
            true;

    public const bool
        EmailRecoveryMayNotReplaceUsbMutationRootKey = true;

    public const bool
        EmailRecoveryMayNotExportUsbMutationRootKey = true;

    public const bool
        EmailRecoveryMayNotReissueUsbMutationRootKey = true;

    // ---------------------------------------------------------------
    // Separation of the two developer verification modes
    // ---------------------------------------------------------------

    public const bool
        NormalUsbModeMustNotRequireEmailVerification = true;

    public const bool
        UsbUnavailableEmailModeMustNotRequireUnavailableUsbVerification =
            true;

    public const bool
        UsbAndEmailMustNotBeConvertedIntoSimultaneousRequirement = true;

    public const bool
        EmailRecoveryMustNotSilentlyReplaceAvailableUsbPath = true;

    // ---------------------------------------------------------------
    // Other credentials / environmental state cannot satisfy A14
    // ---------------------------------------------------------------

    public const bool AdministratorStatusAloneMustNotApproveWorkload = true;

    public const bool UserDeviceKeyAloneMustNotApproveWorkload = true;

    public const bool UserLoginAloneMustNotApproveWorkload = true;

    public const bool ProductionFlagAloneMustNotApproveWorkload = true;

    public const bool TeeResultAloneMustNotApproveWorkload = true;

    public const bool AttestationResultAloneMustNotApproveWorkload = true;

    // ---------------------------------------------------------------
    // Downstream authority must remain absent
    // ---------------------------------------------------------------

    public const bool ApprovedWorkloadMayNotGrantDeveloperSourceAccess = true;

    public const bool ApprovedWorkloadMayNotGrantSourceMutationAuthority = true;

    public const bool ApprovedWorkloadMayNotGrantSigningAuthority = true;

    public const bool ApprovedWorkloadMayNotGrantProductionAuthorization = true;

    public const bool ApprovedWorkloadMayNotGrantTeeAuthorization = true;

    public const bool ApprovedWorkloadMayNotGrantUmbrellaRootAuthority = true;

    // ---------------------------------------------------------------
    // Fail-closed invariants
    // ---------------------------------------------------------------

    public const bool FallbackApprovalForbidden = true;

    public const bool ExceptionApprovalForbidden = true;

    public const bool UnknownStateApprovalForbidden = true;

    public const bool FailOpenForbidden = true;

    public const bool DefaultDecisionMustRemainDeny = true;
}