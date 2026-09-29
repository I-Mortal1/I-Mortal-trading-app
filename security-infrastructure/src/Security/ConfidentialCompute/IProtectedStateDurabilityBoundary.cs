namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IProtectedStateDurabilityBoundary
{
    bool IsTransactionDataDurable(
        ProtectedStateRecoveryRecord record);

    bool IsCommitMarkerDurable(
        ProtectedStateRecoveryRecord record);
}