namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Read-only decision boundary for the I-Mortal user-device
/// proof-of-possession signature-algorithm allowlist.
///
/// An implementation may answer only whether an exact signature-algorithm
/// identifier and exact enrolled public-key-algorithm identifier form an
/// approved pair.
///
/// This interface performs no:
/// - cryptographic operation,
/// - signature verification,
/// - signing,
/// - algorithm negotiation,
/// - algorithm normalization,
/// - alias resolution,
/// - fallback selection,
/// - key access,
/// - authentication,
/// - login authorization,
/// - registration,
/// - device enrollment,
/// - device revocation,
/// - challenge generation,
/// - challenge consumption,
/// - replay-state access,
/// - network I/O,
/// - hardware access,
/// - source mutation,
/// - TEE activation,
/// - attestation activation,
/// - production authorization.
///
/// Unknown, null, empty, malformed, mismatched, aliased, case-varied,
/// substituted, or downgraded identifiers must be rejected by an
/// implementation.
///
/// A true result means only that the exact algorithm pair is admitted by
/// the algorithm policy. It does not mean that a signature is valid,
/// a device is authenticated, a user may log in, or any authorization
/// has been granted.
/// </summary>
public interface IUserDeviceProofOfPossessionSignatureAlgorithmAllowlist
{
    /// <summary>
    /// Returns true only when both identifiers exactly match one approved
    /// signature/public-key algorithm pair.
    ///
    /// The implementation must use ordinal, case-sensitive comparison and
    /// must fail closed for every unknown or mismatched input.
    /// </summary>
    bool IsAllowed(
        string signatureAlgorithm,
        string publicKeyAlgorithm);
}