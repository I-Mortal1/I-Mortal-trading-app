namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Contract for deriving an I-Mortal cryptographic user-device fingerprint
/// digest from already-canonicalized public device-identity material.
///
/// Implementations MUST conform to
/// UserDeviceFingerprintDigestContract.
///
/// The input MUST be the deterministic canonical byte representation produced
/// under the IUserDeviceFingerprintCanonicalSerializer /
/// UserDeviceFingerprintCanonicalSerializer contract.
///
/// The digest is identification and device-binding material only.
///
/// A fingerprint MUST NOT be treated as an authentication secret,
/// bearer credential, authorization token, private key, account key,
/// developer credential, source-access credential, or production credential.
///
/// Successful device authentication requires a separate fresh challenge and
/// proof-of-possession operation using the corresponding hardware-backed,
/// non-exportable device private key.
///
/// This interface grants no authority and performs no operation by itself.
/// </summary>
public interface IUserDeviceFingerprintDigest
{
    /// <summary>
    /// Derives the fixed-length I-Mortal device fingerprint digest from an
    /// already-canonicalized public device-identity byte sequence.
    ///
    /// Implementations must fail closed for null, empty, malformed,
    /// non-canonical, oversized, or otherwise invalid input.
    ///
    /// Implementations must use the algorithm, digest length, and domain
    /// separation defined by UserDeviceFingerprintDigestContract.
    /// </summary>
    /// <param name="canonicalDeviceIdentity">
    /// Deterministic canonical public device-identity serialization.
    /// Private-key material is forbidden.
    /// </param>
    /// <returns>
    /// A newly allocated fixed-length fingerprint digest.
    /// </returns>
    byte[] ComputeDigest(
        byte[] canonicalDeviceIdentity);
}