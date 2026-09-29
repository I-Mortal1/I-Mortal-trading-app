using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Independent fail-closed verification boundary for establishing that
/// untrusted evidence corresponds to the exact required VeraCrypt backing
/// source used for developer source custody.
///
/// Implementations must independently establish all required bindings,
/// including:
///
/// - challenge identity,
/// - challenge freshness,
/// - custody identifier,
/// - key identifier,
/// - exact volume identity,
/// - key-object identity,
/// - authorized USB identity digest,
/// - backing-source identity,
/// - cryptographic challenge binding.
///
/// Caller assertions are insufficient.
///
/// A successful result is developer source-custody evidence only.
///
/// It does not independently grant source mutation, production authorization,
/// trading authority, provider-dispatch authority, signing authority, user
/// runtime authority, or I-Mortal Security Umbrella root authority.
///
/// Implementations must fail closed.
/// </summary>
public interface IVeraCryptBackingSourceVerifier
{
    bool Verify(
        VeraCryptBackingSourceChallenge challenge,
        VeraCryptBackingSourceEvidence evidence,
        VeraCryptUsbKeyCustodyDescriptor requiredCustody,
        DateTimeOffset now);
}