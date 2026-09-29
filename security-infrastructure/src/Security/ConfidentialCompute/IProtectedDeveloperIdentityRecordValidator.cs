using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Fail-closed validation boundary for an immutable
/// <see cref="ProtectedDeveloperIdentity"/> record.
///
/// Validation must establish the structural and cryptographic integrity of the
/// protected identity record without recovering the protected plaintext
/// developer identity.
///
/// A conforming implementation must validate, at minimum:
///
/// - the identity version is valid;
/// - all required encrypted identity envelopes are structurally valid;
/// - all required keyed identity commitments are present and structurally valid;
/// - the required VeraCrypt USB custody binding is present and structurally valid;
/// - the previous-record digest obeys the identity-version chain rules;
/// - the stored identity integrity digest is present and structurally valid;
/// - the integrity digest recomputed from the authoritative canonical identity
///   bytes exactly matches the stored identity integrity digest.
///
/// Validation must use
/// <see cref="IProtectedDeveloperIdentityCanonicalSerializer"/>
/// as the authoritative canonicalization boundary and
/// <see cref="IProtectedDeveloperIdentityIntegrityDigestCalculator"/>
/// as the authoritative integrity-digest calculation boundary.
///
/// Implementations must fail closed on null, malformed, inconsistent,
/// unsupported, unverifiable, or cryptographically invalid records and on any
/// dependency exception.
///
/// Successful validation establishes record integrity only.
///
/// Successful validation does not independently grant:
///
/// - source-mutation authority;
/// - developer source authority;
/// - production authorization;
/// - trading authority;
/// - provider-dispatch authority;
/// - signing authority;
/// - key-unwrapping authority;
/// - identity-enrollment authority;
/// - identity-rotation authority;
/// - plaintext identity recovery authority;
/// - user runtime authority;
/// - I-Mortal Security Umbrella root authority.
/// </summary>
public interface IProtectedDeveloperIdentityRecordValidator
{
    /// <summary>
    /// Validates the supplied protected developer identity record.
    ///
    /// The method must return false for every invalid or unverifiable record.
    /// Implementations must not interpret successful validation as an
    /// authorization decision.
    /// </summary>
    /// <param name="identity">
    /// Protected developer identity record to validate.
    /// </param>
    /// <returns>
    /// True only when the record satisfies the complete structural and
    /// cryptographic integrity contract; otherwise false.
    /// </returns>
    bool Validate(
        ProtectedDeveloperIdentity identity);
}