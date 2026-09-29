namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IProtectedStateRecoveryBoundary
{
    ProtectedStateRecoveryDisposition Evaluate(
        ProtectedStateRecoveryRecord record,
        ProtectedStateSnapshot authoritativeState);
}