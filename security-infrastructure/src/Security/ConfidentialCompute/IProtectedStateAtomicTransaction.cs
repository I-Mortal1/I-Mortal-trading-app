namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IProtectedStateAtomicTransaction
{
    ProtectedStateAtomicTransactionResult TryCommit(
        ProtectedStateCommitRequest request);
}