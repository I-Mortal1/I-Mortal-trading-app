using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Complete independently controlled developer email-recovery verifier.
///
/// A successful implementation must establish ALL of:
/// - USB unavailability,
/// - developer identity,
/// - email verification,
/// - cryptographic challenge binding,
/// - freshness,
/// - replay protection,
/// - scoped recovery authorization.
///
/// Implementations must fail closed.
///
/// Successful verification remains source-custody evidence only.
/// </summary>
public interface IDeveloperEmailRecoveryVerifier
{
    bool Verify(
        DeveloperEmailRecoveryChallenge challenge,
        DeveloperEmailRecoveryEvidence evidence,
        DateTimeOffset now);
}