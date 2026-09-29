namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IProtectedStateReplayGuard
{
    bool TryConsume(
        ProtectedStateCommitRequest request);
}
