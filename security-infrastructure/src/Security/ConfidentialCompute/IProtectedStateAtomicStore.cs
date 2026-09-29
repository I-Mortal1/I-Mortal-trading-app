namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IProtectedStateAtomicStore
{
    ProtectedStateSnapshot GetCurrent();

    bool TryCompareAndCommit(
        long expectedCurrentVersion,
        byte[] expectedCurrentStateDigest,
        ProtectedStateSnapshot resultingState);
}
