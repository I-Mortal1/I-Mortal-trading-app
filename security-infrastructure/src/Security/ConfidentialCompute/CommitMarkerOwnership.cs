using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class CommitMarkerOwnership
{
    public CommitMarkerOwnership(
        ConfidentialSecurityBoundaryIdentity boundaryIdentity,
        bool requiresDurableTransactionData = true,
        bool requiresTransactionBinding = true,
        bool requiresStateBinding = true,
        bool requiresReplayBinding = true,
        bool requiresRecoveryRecordBinding = true)
    {
        BoundaryIdentity = boundaryIdentity
            ?? throw new ArgumentNullException(nameof(boundaryIdentity));

        if (!requiresDurableTransactionData ||
            !requiresTransactionBinding ||
            !requiresStateBinding ||
            !requiresReplayBinding ||
            !requiresRecoveryRecordBinding)
        {
            throw new ArgumentException(
                "Commit-marker ownership requirements may not be weakened.");
        }

        RequiresDurableTransactionData = true;
        RequiresTransactionBinding = true;
        RequiresStateBinding = true;
        RequiresReplayBinding = true;
        RequiresRecoveryRecordBinding = true;
    }

    public ConfidentialSecurityBoundaryIdentity BoundaryIdentity { get; }

    public bool RequiresDurableTransactionData { get; }

    public bool RequiresTransactionBinding { get; }

    public bool RequiresStateBinding { get; }

    public bool RequiresReplayBinding { get; }

    public bool RequiresRecoveryRecordBinding { get; }
}