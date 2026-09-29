using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Independently verifies that ProjectIntegrityEvidence was cryptographically
/// bound to the exact authoritative AttestationChallenge.
///
/// This contract is evidence verification only.
/// It grants no source-mutation or production authority.
/// </summary>
public interface IProjectIntegrityChallengeBindingVerifier
{
    bool Verify(
        ProjectIntegrityEvidence evidence,
        AttestationChallenge challenge,
        DateTimeOffset now);
}