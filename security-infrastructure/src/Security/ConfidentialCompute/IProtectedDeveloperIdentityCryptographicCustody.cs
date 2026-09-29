using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Cryptographic-custody boundary for protected developer identity fields.
///
/// A production implementation must provide independently domain-separated
/// authenticated encryption and keyed commitments for:
///
/// - complete canonical USB identity;
/// - canonical USB identification number;
/// - canonical developer recovery email.
///
/// Required authenticated encryption:
///
///     AES-256-GCM
///
/// Required parameters:
///
///     key       = 256 bits
///     nonce     = 96 bits
///     auth tag  = 128 bits
///
/// Required keyed commitment:
///
///     HMAC-SHA-256
///
/// Encryption keys and commitment keys must be independently
/// purpose-separated.
///
/// Production root cryptographic material must be hardware-backed and must not
/// be embedded in source code, configuration, environment variables,
/// command-line arguments, logs, telemetry, or plaintext temporary files.
///
/// Implementations must fail closed.
///
/// Cryptographic success grants no source-mutation, project, production,
/// trading, provider-dispatch, signing, user-runtime, or I-Mortal Security
/// Umbrella root authority.
/// </summary>
public interface IProtectedDeveloperIdentityCryptographicCustody
{
    CryptographicContractEnvelope Protect(
        ProtectedDeveloperIdentityField field,
        ReadOnlySpan<byte> canonicalPlaintext,
        ReadOnlySpan<byte> canonicalAssociatedData);

    byte[] Unprotect(
        ProtectedDeveloperIdentityField field,
        CryptographicContractEnvelope envelope,
        ReadOnlySpan<byte> canonicalAssociatedData);

    byte[] CalculateCommitment(
        ProtectedDeveloperIdentityField field,
        ReadOnlySpan<byte> canonicalPlaintext);

    bool VerifyCommitment(
        ProtectedDeveloperIdentityField field,
        ReadOnlySpan<byte> canonicalPlaintext,
        ReadOnlySpan<byte> expectedCommitment);
}