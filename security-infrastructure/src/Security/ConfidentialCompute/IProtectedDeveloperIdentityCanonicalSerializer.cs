namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Deterministically serializes a protected developer identity into the
/// canonical byte representation used by the I-Mortal Security Umbrella.
///
/// The stored IdentityRecordIntegrityDigest is intentionally excluded from
/// canonical serialization to prevent self-referential hashing.
///
/// Implementations must be deterministic and fail closed.
///
/// This interface grants no authority.
/// </summary>
public interface IProtectedDeveloperIdentityCanonicalSerializer
{
    byte[] SerializeForIntegrity(
        ProtectedDeveloperIdentity identity);
}