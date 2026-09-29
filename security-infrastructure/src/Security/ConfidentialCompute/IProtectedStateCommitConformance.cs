namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IProtectedStateCommitConformance
{
    bool Validate(
        ProtectedStateCommitRequest request,
        ProtectedStateSnapshot currentState);
}
