namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable implementation contract for the A14 approved-workload
/// gate adapter boundary.
///
/// SECURITY MODEL
/// ==============
///
/// Approved-workload authorization MUST remain transaction-bound.
///
/// A successful trusted-evidence evaluation MUST NOT be transformed into:
///
/// - a process-global approval boolean,
/// - a static approval flag,
/// - a singleton last-success value,
/// - cached reusable approval,
/// - caller-asserted approval,
/// - mutable ambient authorization state,
/// - an unbound reusable authorization token.
///
/// The eventual adapter MUST derive its decision from the exact
/// authoritative evaluation context.
///
/// REQUIRED AUTHORITATIVE INPUTS
/// =============================
///
/// Every approved-workload evaluation must remain bound to:
///
/// 1. ProjectIntegrityEvidence
/// 2. ProjectIntegrityPolicy
/// 3. AttestationChallenge
/// 4. evaluation time
///
/// The adapter MUST use
/// IApprovedWorkloadTrustedEvidenceBoundary.
///
/// It MUST NOT independently recreate project-integrity verification,
/// challenge-binding verification, workload-digest verification, or
/// caller-controlled approval.
///
/// CHALLENGE / REPLAY REQUIREMENTS
/// ===============================
///
/// Approval from one challenge MUST NOT authorize another challenge.
///
/// Approval from one workload MUST NOT authorize another workload.
///
/// Approval from one project-integrity evidence instance MUST NOT become
/// ambient authority for later evaluations.
///
/// Expired, stale, absent, malformed, mismatched, or unverifiable evidence
/// MUST result in denial.
///
/// LIFETIME REQUIREMENTS
/// =====================
///
/// The approved-workload decision MUST be evaluation-scoped.
///
/// No static mutable authorization state is permitted.
///
/// No process-wide mutable approval state is permitted.
///
/// No cross-request approval cache is permitted.
///
/// No cross-challenge approval reuse is permitted.
///
/// No cross-workload approval reuse is permitted.
///
/// No fallback from missing transaction evidence is permitted.
///
/// ROOT COMPOSITION REQUIREMENT
/// ============================
///
/// IMortalSecurityUmbrellaRoot MUST NOT receive an approved-workload
/// success unless that success was established from the exact trusted
/// evidence associated with the same root authorization evaluation.
///
/// The current parameterless IApprovedWorkloadGate.IsApproved() contract
/// MUST NOT be bridged by ambient mutable state.
///
/// Before a real approving implementation can replace
/// DenyAllApprovedWorkloadGate, the adapter/root contract must provide a
/// structurally transaction-bound method of supplying the authoritative
/// evaluation context.
///
/// AUTHORITY SEPARATION
/// ====================
///
/// Successful approved-workload verification is only one prerequisite.
///
/// It does not independently grant:
///
/// - source mutation authority,
/// - developer source authority,
/// - production authorization,
/// - signing authority,
/// - TEE authorization,
/// - attestation authorization,
/// - workload execution authority,
/// - trading authority,
/// - provider-dispatch authority,
/// - user-runtime authority,
/// - I-Mortal Security Umbrella root authority.
///
/// The complete security chain remains strict AND-only.
///
/// Developer verification
/// AND
/// project-integrity authorization
/// AND
/// approved-workload authorization
/// AND
/// TEE attestation
/// AND
/// all remaining security-policy requirements.
///
/// Any missing, false, stale, malformed, mismatched, exceptional, or
/// unverifiable prerequisite MUST deny.
///
/// USB / EMAIL SEPARATION
/// ======================
///
/// Developer identity verification remains a separate security function.
///
/// Normal developer path:
///     USB / VeraCrypt verification.
///
/// Recovery developer path:
///     pre-registered email verification,
///     permitted only when the USB is unavailable.
///
/// USB and email are NOT simultaneous authentication requirements.
///
/// Email recovery MUST NOT replace:
///
/// - the USB mutation root key,
/// - project-integrity verification,
/// - approved-workload verification,
/// - TEE attestation,
/// - strict source-mutation authorization.
///
/// DEFAULT
/// =======
///
/// DENY.
///
/// No exception authorizes.
/// No fallback authorizes.
/// No partial success authorizes.
/// </summary>
public static class ApprovedWorkloadGateAdapterContract
{
    public const bool TransactionBoundEvaluationRequired = true;

    public const bool TrustedEvidenceBoundaryRequired = true;

    public const bool ExactProjectIntegrityEvidenceRequired = true;

    public const bool ExactProjectIntegrityPolicyRequired = true;

    public const bool ExactAttestationChallengeRequired = true;

    public const bool EvaluationTimeRequired = true;

    public const bool ProcessGlobalApprovalForbidden = true;

    public const bool StaticMutableApprovalForbidden = true;

    public const bool CachedApprovalForbidden = true;

    public const bool CallerAssertedApprovalForbidden = true;

    public const bool AmbientMutableAuthorizationForbidden = true;

    public const bool CrossChallengeReuseForbidden = true;

    public const bool CrossWorkloadReuseForbidden = true;

    public const bool CrossEvidenceReuseForbidden = true;

    public const bool MissingEvidenceFallbackForbidden = true;

    public const bool ParameterlessAmbientBridgeForbidden = true;

    public const bool RootEvaluationBindingRequired = true;

    public const bool SourceMutationAuthorityGranted = false;

    public const bool ProductionAuthorizationGranted = false;

    public const bool TeeAuthorizationGranted = false;

    public const bool AttestationAuthorizationGranted = false;

    public const bool DefaultDecision = false;

    public const bool FailOpenAllowed = false;
}