using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Independent cryptographic proof-of-possession verification boundary.
///
/// Implementations must validate the proof against the expected challenge
/// and required VeraCrypt USB custody descriptor.
///
/// Implementations must fail closed.
///
/// Successful verification is evidence only and does not independently grant
/// source-mutation, production, trading, provider-dispatch, or root authority.
/// </summary>
public interface IDeveloperProofOfPossessionVerifier
{
    bool Verify(
        DeveloperProofOfPossessionChallenge challenge,
        DeveloperProofOfPossessionEvidence evidence,
        VeraCryptUsbKeyCustodyDescriptor requiredCustody,
        DateTimeOffset now);
}