using System.Threading;
using System.Threading.Tasks;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IDurabilityOwnershipVerifier
{
    ValueTask<DurabilityProof> VerifyAsync(
        ProtectedStateCommitMarker commitMarker,
        DurabilityOwnership ownership,
        CancellationToken cancellationToken = default);
}