using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class DurabilityOwnership
{
    public DurabilityOwnership(
        ConfidentialSecurityBoundaryIdentity boundaryIdentity,
        bool requiresStatePersistence = true,
        bool requiresReplayPersistence = true,
        bool requiresRecoveryRecordPersistence = true,
        bool requiresCommitMarkerPersistence = true,
        bool requiresStateReplayConsistency = true)
    {
        BoundaryIdentity = boundaryIdentity
            ?? throw new ArgumentNullException(nameof(boundaryIdentity));

        if (!requiresStatePersistence ||
            !requiresReplayPersistence ||
            !requiresRecoveryRecordPersistence ||
            !requiresCommitMarkerPersistence ||
            !requiresStateReplayConsistency)
        {
            throw new ArgumentException(
                "Durability ownership requirements may not be weakened.");
        }

        RequiresStatePersistence = true;
        RequiresReplayPersistence = true;
        RequiresRecoveryRecordPersistence = true;
        RequiresCommitMarkerPersistence = true;
        RequiresStateReplayConsistency = true;
    }

    public ConfidentialSecurityBoundaryIdentity BoundaryIdentity { get; }

    public bool RequiresStatePersistence { get; }

    public bool RequiresReplayPersistence { get; }

    public bool RequiresRecoveryRecordPersistence { get; }

    public bool RequiresCommitMarkerPersistence { get; }

    public bool RequiresStateReplayConsistency { get; }
}