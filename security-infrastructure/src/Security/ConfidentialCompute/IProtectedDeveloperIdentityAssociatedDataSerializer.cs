namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Deterministic canonical associated-data serialization boundary for
/// protected developer identity cryptography.
///
/// Implementations must use explicit deterministic binary canonicalization,
/// explicit field framing, domain separation, and fail-closed validation.
///
/// Implementations must bind:
///
/// - I-Mortal Security Umbrella identity;
/// - protected-identity schema/version context;
/// - IdentityVersion;
/// - protected field purpose;
/// - cryptographic domain;
/// - key identifier;
/// - required VeraCrypt USB custody descriptor;
/// - PreviousIdentityRecordDigest.
///
/// JSON, reflection-dependent property ordering, culture-dependent formatting,
/// and platform-dependent formatting are prohibited for cryptographic
/// canonicalization.
///
/// This interface grants no authority.
/// </summary>
public interface IProtectedDeveloperIdentityAssociatedDataSerializer
{
    byte[] Serialize(
        long identityVersion,
        ProtectedDeveloperIdentityField field,
        string cryptographicDomain,
        string keyIdentifier,
        VeraCryptUsbKeyCustodyDescriptor requiredCustody,
        byte[] previousIdentityRecordDigest);
}