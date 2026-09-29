namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Contract for deterministic canonical serialization of the public,
/// non-secret inputs from which an I-MORTAL user-device cryptographic
/// fingerprint may later be derived.
///
/// SECURITY BOUNDARY
/// -----------------
///
/// This interface defines serialization only.
///
/// It MUST NOT:
///
/// - hash the canonical bytes;
/// - generate a fingerprint digest;
/// - generate or provision a cryptographic key;
/// - unwrap or export a private key;
/// - access TPM, Secure Enclave, StrongBox, Android Keystore,
///   Linux TPM, VeraCrypt, or developer USB material;
/// - perform proof-of-possession;
/// - authenticate a user;
/// - enroll or revoke a device;
/// - issue a session;
/// - perform QR generation or scanning;
/// - perform network I/O;
/// - grant developer authority;
/// - grant source access or source-mutation authority;
/// - grant signing, TEE, attestation, or production authority.
///
/// Canonicalization is governed by
/// UserDeviceFingerprintCanonicalizationBoundary.
///
/// The resulting canonical bytes are identification/binding input only.
/// They are not a password, private key, bearer credential,
/// authentication decision, authorization decision, or
/// proof-of-possession.
///
/// Each enrolled device retains its own hardware-backed, non-exportable
/// private key. No private key is transferred or synchronized between
/// devices.
///
/// Future registration, login, QR authentication, device enrollment,
/// recovery, revocation, and session issuance are separate operations
/// and must pass the I-MORTAL confidential identity-plane and
/// attested-workload gates before those operations may become
/// authoritative.
/// </summary>
public interface IUserDeviceFingerprintCanonicalSerializer
{
    /// <summary>
    /// Serializes fingerprint identity inputs into the exact deterministic
    /// binary representation defined by the authoritative fingerprint
    /// canonicalization boundary.
    ///
    /// Implementations MUST fail closed for invalid, missing, unsupported,
    /// ambiguous, or non-canonical input.
    ///
    /// This method performs serialization only.
    /// </summary>
    /// <param name="accountIdentity">
    /// Stable I-MORTAL account-binding identifier.
    /// This value is not an authorization credential.
    /// </param>
    /// <param name="publicKeyAlgorithm">
    /// Canonical identifier for the device public-key algorithm.
    /// </param>
    /// <param name="canonicalPublicKey">
    /// Canonical public representation of the per-device public key.
    /// This MUST NOT contain private-key material.
    /// </param>
    /// <param name="platformClass">
    /// Canonical platform class such as Windows, Apple, Android, or Linux.
    /// </param>
    /// <param name="providerClass">
    /// Canonical approved hardware-key provider class.
    /// </param>
    /// <param name="keyPurpose">
    /// Canonical I-MORTAL device-key purpose identifier.
    /// </param>
    /// <returns>
    /// Deterministic canonical binary bytes suitable as input to a
    /// separate fingerprint digest operation.
    /// </returns>
    byte[] Serialize(
        string accountIdentity,
        string publicKeyAlgorithm,
        byte[] canonicalPublicKey,
        string platformClass,
        string providerClass,
        string keyPurpose);
}