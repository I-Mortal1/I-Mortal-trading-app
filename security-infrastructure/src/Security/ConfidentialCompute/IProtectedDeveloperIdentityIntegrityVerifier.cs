namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Independently verifies the integrity digest of a protected developer
/// identity using its deterministic canonical representation.
///
/// Successful verification establishes integrity evidence only.
///
/// It does not grant source mutation, production, signing, trading,
/// provider-dispatch, user-runtime, or Security Umbrella root authority.
///
/// Implementations must fail closed.
/// </summary>
public interface IProtectedDeveloperIdentityIntegrityVerifier
{
    bool Verify(
        ProtectedDeveloperIdentity identity);
}