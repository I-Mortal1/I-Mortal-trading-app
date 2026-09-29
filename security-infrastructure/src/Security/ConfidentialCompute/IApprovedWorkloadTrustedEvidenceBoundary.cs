using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Independent trusted-evidence boundary for the approved-workload
/// authorization prerequisite.
///
/// This boundary does not accept caller-asserted workload approval.
///
/// A true result requires the authoritative project-integrity composition
/// to accept the exact ProjectIntegrityEvidence against:
///
/// - the independently trusted ProjectIntegrityPolicy,
/// - the exact authoritative AttestationChallenge,
/// - the current evaluation time.
///
/// The approved-workload identity is therefore carried by the
/// ApprovedWorkloadDigest already bound into ProjectIntegrityEvidence and
/// independently required by ProjectIntegrityPolicy.
///
/// A true result establishes only the approved-workload trusted-evidence
/// prerequisite.
///
/// It does not grant source mutation, signing, production authorization,
/// TEE authorization, workload execution, trading authority,
/// provider-dispatch authority, user-runtime authority, developer source
/// authority, or I-Mortal Security Umbrella root authority.
///
/// Implementations must fail closed.
/// </summary>
public interface IApprovedWorkloadTrustedEvidenceBoundary
{
    bool Verify(
        ProjectIntegrityEvidence evidence,
        ProjectIntegrityPolicy requiredPolicy,
        AttestationChallenge challenge,
        DateTimeOffset now);
}