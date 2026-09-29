using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class BoundaryOwnershipEvidence
{
    internal BoundaryOwnershipEvidence(
        ConfidentialSecurityBoundaryIdentity expectedBoundary,
        ConfidentialSecurityBoundaryIdentity verifiedBoundary,
        VerificationEvidenceBinding binding)
    {
        ExpectedBoundary = expectedBoundary
            ?? throw new ArgumentNullException(nameof(expectedBoundary));

        VerifiedBoundary = verifiedBoundary
            ?? throw new ArgumentNullException(nameof(verifiedBoundary));

        Binding = binding
            ?? throw new ArgumentNullException(nameof(binding));
    }

    public ConfidentialSecurityBoundaryIdentity ExpectedBoundary { get; }

    public ConfidentialSecurityBoundaryIdentity VerifiedBoundary { get; }

    public VerificationEvidenceBinding Binding { get; }
}
