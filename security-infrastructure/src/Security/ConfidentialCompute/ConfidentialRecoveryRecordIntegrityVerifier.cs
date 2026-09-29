using System;
using System.Security.Cryptography;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

internal sealed class ConfidentialRecoveryRecordIntegrityVerifier
{
    public bool Verify(
        ReadOnlySpan<byte> canonicalRecoveryRecord,
        ReadOnlySpan<byte> expectedDigest)
    {
        if (canonicalRecoveryRecord.IsEmpty ||
            expectedDigest.IsEmpty)
        {
            return false;
        }

        try
        {
            byte[] computed =
                SHA256.HashData(canonicalRecoveryRecord);

            return CryptographicOperations.FixedTimeEquals(
                computed,
                expectedDigest);
        }
        catch
        {
            return false;
        }
    }
}
