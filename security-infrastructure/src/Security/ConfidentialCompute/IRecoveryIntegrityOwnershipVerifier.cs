using System.Threading;
using System.Threading.Tasks;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IRecoveryIntegrityOwnershipVerifier
{
    ValueTask<RecoveryRecordIntegrityVerification> VerifyAsync(
        ProtectedStateRecoveryRecord recoveryRecord,
        RecoveryIntegrityOwnership ownership,
        CancellationToken cancellationToken = default);
}