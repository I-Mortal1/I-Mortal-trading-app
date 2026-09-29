using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Cryptographic integrity-digest calculation boundary for an immutable
/// ProtectedDeveloperIdentity record.
///
/// Implementations must:
///
/// - canonicalize the supplied identity through the authoritative
///   IProtectedDeveloperIdentityCanonicalSerializer;
/// - calculate a cryptographic digest over exactly those canonical bytes;
/// - use a fixed, explicitly defined digest algorithm;
/// - return a new digest byte array owned by the caller;
/// - fail closed for null, malformed, unsupported, or otherwise invalid input.
///
/// Implementations must not:
///
/// - decrypt the complete USB identity;
/// - decrypt the USB ID number;
/// - decrypt the recovery email address;
/// - unwrap identity-encryption keys;
/// - read VeraCrypt USB key material;
/// - perform enrollment or rotation;
/// - mutate the ProtectedDeveloperIdentity;
/// - perform network access;
/// - grant source-mutation authority;
/// - grant production authorization;
/// - grant trading, signing, provider-dispatch, user-runtime, or root authority.
///
/// A successfully calculated digest is integrity evidence only.
///
/// The digest is not, by itself, an authorization factor.
/// </summary>
public interface IProtectedDeveloperIdentityIntegrityDigestCalculator
{
    /// <summary>
    /// Calculates the cryptographic integrity digest for the supplied
    /// ProtectedDeveloperIdentity using its canonical integrity representation.
    ///
    /// Implementations must fail closed.
    /// </summary>
    /// <param name="identity">
    /// Immutable protected developer identity whose integrity digest is
    /// required.
    /// </param>
    /// <returns>
    /// Newly allocated cryptographic integrity-digest bytes.
    /// </returns>
    byte[] Calculate(
        ProtectedDeveloperIdentity identity);
}