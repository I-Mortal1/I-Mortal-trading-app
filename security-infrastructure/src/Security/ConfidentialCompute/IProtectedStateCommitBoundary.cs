namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IProtectedStateCommitBoundary
{
    ProtectedStateCommitResult Commit(
        ProtectedStateCommitRequest request);
}
