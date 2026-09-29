using System;
using System.Security.Cryptography;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Fail-closed SHA-256 integrity verifier for ProtectedDeveloperIdentity.
///
/// This verifier recomputes the digest from the canonical protected identity
/// representation and compares it to the stored digest in fixed time.
///
/// This is integrity evidence only.
///
/// It does not authenticate the actor that created the record and does not
/// independently grant any source-mutation or production authority.
/// </summary>
public sealed class ProtectedDeveloperIdentityIntegrityVerifier :
    IProtectedDeveloperIdentityIntegrityVerifier
{
    private const int Sha256Length = 32;

    private readonly
        IProtectedDeveloperIdentityCanonicalSerializer _serializer;

    public ProtectedDeveloperIdentityIntegrityVerifier(
        IProtectedDeveloperIdentityCanonicalSerializer serializer)
    {
        _serializer =
            serializer
            ?? throw new ArgumentNullException(nameof(serializer));
    }

    public bool Verify(
        ProtectedDeveloperIdentity identity)
    {
        if (identity is null)
        {
            return false;
        }

        try
        {
            var expectedDigest =
                identity.IdentityRecordIntegrityDigest;

            if (expectedDigest is null ||
                expectedDigest.Length != Sha256Length)
            {
                return false;
            }

            var canonicalBytes =
                _serializer.SerializeForIntegrity(identity);

            if (canonicalBytes is null ||
                canonicalBytes.Length == 0)
            {
                return false;
            }

            var actualDigest =
                SHA256.HashData(canonicalBytes);

            if (actualDigest.Length != Sha256Length)
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(
                actualDigest,
                expectedDigest);
        }
        catch
        {
            return false;
        }
    }
}