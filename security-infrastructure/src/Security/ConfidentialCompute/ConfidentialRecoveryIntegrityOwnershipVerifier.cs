using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

internal sealed class ConfidentialRecoveryIntegrityOwnershipVerifier
{
    public bool Verify(
        ConfidentialSecurityBoundaryIdentity expectedBoundary,
        ConfidentialSecurityBoundaryIdentity actualBoundary)
    {
        if (expectedBoundary is null ||
            actualBoundary is null)
        {
            return false;
        }

        return ReferenceEquals(
            expectedBoundary,
            actualBoundary);
    }
}
