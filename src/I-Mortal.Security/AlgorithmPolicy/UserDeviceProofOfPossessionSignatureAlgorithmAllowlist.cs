using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Fail-closed V1 implementation of the I-Mortal user-device
/// proof-of-possession signature-algorithm allowlist.
///
/// This implementation recognizes exactly one approved V1 pair:
///
/// Signature algorithm:
/// ECDSA-P256-SHA256-P1363
///
/// Public-key algorithm:
/// EC-P256
///
/// Matching is exact, ordinal, and case-sensitive.
///
/// This type performs no cryptographic operation and grants no
/// authentication or authorization.
/// </summary>
public sealed class UserDeviceProofOfPossessionSignatureAlgorithmAllowlist :
    IUserDeviceProofOfPossessionSignatureAlgorithmAllowlist
{
    public const string ApprovedSignatureAlgorithm =
        "ECDSA-P256-SHA256-P1363";

    public const string ApprovedPublicKeyAlgorithm =
        "EC-P256";

    public bool IsAllowed(
        string signatureAlgorithm,
        string publicKeyAlgorithm)
    {
        if (signatureAlgorithm is null ||
            publicKeyAlgorithm is null)
        {
            return false;
        }

        if (signatureAlgorithm.Length == 0 ||
            publicKeyAlgorithm.Length == 0)
        {
            return false;
        }

        return
            string.Equals(
                signatureAlgorithm,
                ApprovedSignatureAlgorithm,
                StringComparison.Ordinal) &&
            string.Equals(
                publicKeyAlgorithm,
                ApprovedPublicKeyAlgorithm,
                StringComparison.Ordinal);
    }
}