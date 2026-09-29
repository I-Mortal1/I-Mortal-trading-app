using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class RecoveryIntegrityOwnership
{
    public RecoveryIntegrityOwnership(
        ConfidentialSecurityBoundaryIdentity boundaryIdentity,
        bool requiresCanonicalSerialization = true,
        bool requiresTransactionBinding = true,
        bool requiresStateBinding = true,
        bool requiresReplayBinding = true,
        bool requiresBoundaryIdentityBinding = true)
    {
        BoundaryIdentity = boundaryIdentity
            ?? throw new ArgumentNullException(nameof(boundaryIdentity));

        if (!requiresCanonicalSerialization ||
            !requiresTransactionBinding ||
            !requiresStateBinding ||
            !requiresReplayBinding ||
            !requiresBoundaryIdentityBinding)
        {
            throw new ArgumentException(
                "Recovery integrity ownership requirements may not be weakened.");
        }

        RequiresCanonicalSerialization = true;
        RequiresTransactionBinding = true;
        RequiresStateBinding = true;
        RequiresReplayBinding = true;
        RequiresBoundaryIdentityBinding = true;
    }

    public ConfidentialSecurityBoundaryIdentity BoundaryIdentity { get; }

    public bool RequiresCanonicalSerialization { get; }

    public bool RequiresTransactionBinding { get; }

    public bool RequiresStateBinding { get; }

    public bool RequiresReplayBinding { get; }

    public bool RequiresBoundaryIdentityBinding { get; }
}