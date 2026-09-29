using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Independent fail-closed project-integrity verification boundary.
///
/// Implementations must independently establish all required bindings,
/// including:
///
/// - exact project identity,
/// - exact manifest identity,
/// - approved project-manifest digest,
/// - approved protected-source-tree digest,
/// - approved workload digest,
/// - evidence freshness,
/// - cryptographic challenge binding.
///
/// Caller assertions are insufficient.
///
/// A successful verification result is project-integrity evidence only.
///
/// It does not independently grant source mutation, production
/// authorization, signing authority, workload execution authority,
/// trading authority, provider-dispatch authority, user-runtime authority,
/// developer source authority, or I-Mortal Security Umbrella root authority.
///
/// Implementations must fail closed.
/// </summary>
public interface IProjectIntegrityVerifier
{
    bool Verify(
        ProjectIntegrityEvidence evidence,
        ProjectIntegrityPolicy requiredPolicy,
        DateTimeOffset now);
}