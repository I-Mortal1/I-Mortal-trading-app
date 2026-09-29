using System.Threading;
using System.Threading.Tasks;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IRecoveryDurabilityOwnershipConformance
{
    ValueTask<bool> IsConformantAsync(
        RecoveryRecordIntegrityVerification recoveryIntegrity,
        DurabilityProof durabilityProof,
        ProtectedStateCommitMarker commitMarker,
        RecoveryIntegrityOwnership recoveryOwnership,
        DurabilityOwnership durabilityOwnership,
        CommitMarkerOwnership commitMarkerOwnership,
        CancellationToken cancellationToken = default);
}