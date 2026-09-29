using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Cryptographic key-operation boundary for protected developer identity
/// custody.
///
/// Production implementations must keep root cryptographic material
/// hardware-backed and non-exportable wherever supported by the selected
/// hardware security boundary.
///
/// This contract deliberately exposes cryptographic operations rather than
/// raw secret key bytes.
///
/// Encryption and commitment keys must be independently purpose-separated.
///
/// Implementations must fail closed.
///
/// Successful cryptographic operations grant no source-mutation, project,
/// production, trading, provider-dispatch, signing, user-runtime, or
/// I-Mortal Security Umbrella root authority.
/// </summary>
public interface IProtectedDeveloperIdentityCryptographicKeyProvider
{
    string GetEncryptionKeyIdentifier(
        ProtectedDeveloperIdentityField field);

    string GetCommitmentKeyIdentifier(
        ProtectedDeveloperIdentityField field);

    void EncryptAes256Gcm(
        ProtectedDeveloperIdentityField field,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> associatedData,
        Span<byte> ciphertext,
        Span<byte> authenticationTag);

    void DecryptAes256Gcm(
        ProtectedDeveloperIdentityField field,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> authenticationTag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> plaintext);

    void CalculateHmacSha256(
        ProtectedDeveloperIdentityField field,
        ReadOnlySpan<byte> canonicalPlaintext,
        Span<byte> destination);
}