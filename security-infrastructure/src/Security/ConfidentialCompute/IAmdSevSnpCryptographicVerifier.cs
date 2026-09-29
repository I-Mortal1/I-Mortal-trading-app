namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// AMD SEV-SNP-specific cryptographic verification boundary.
///
/// Implementations must treat raw evidence and embedded collateral as
/// untrusted input. Success from this boundary is not authorization and
/// does not bypass replay protection, measurement policy, the root gate,
/// VeraCrypt/USB policy, or any existing production/trading policy.
///
/// No concrete production verifier is supplied by R36-R10-R3.
/// </summary>
public interface IAmdSevSnpCryptographicVerifier
{
    bool TryVerify(
        AmdSevSnpRawEvidence rawEvidence,
        AttestationChallenge expectedChallenge,
        out AmdSevSnpCryptographicVerification? verification);
}