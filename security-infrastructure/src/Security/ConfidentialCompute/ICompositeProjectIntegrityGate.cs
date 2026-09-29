using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Strict AND-only composition of the independent project-integrity
/// verifier and the exact project-integrity challenge-binding verifier.
///
/// A true result means only that both independent verification boundaries
/// accepted the same ProjectIntegrityEvidence in the same evaluation.
///
/// This result is evidence only.
///
/// It does not grant source mutation, signing, production authorization,
/// workload execution, trading authority, provider-dispatch authority,
/// user-runtime authority, developer source authority, or I-Mortal
/// Security Umbrella root authority.
///
/// Implementations must fail closed.
/// </summary>
public interface ICompositeProjectIntegrityGate
{
    bool Verify(
        ProjectIntegrityEvidence evidence,
        ProjectIntegrityPolicy requiredPolicy,
        AttestationChallenge challenge,
        DateTimeOffset now);
}