namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Single-use recovery-challenge replay boundary.
///
/// Implementations must atomically consume a challenge identifier.
/// Unknown, expired, previously consumed, or invalid identifiers must fail.
/// </summary>
public interface IDeveloperRecoveryReplayLedger
{
    bool TryConsume(string challengeId);
}