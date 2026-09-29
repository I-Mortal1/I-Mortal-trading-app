namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IAttestationReplayLedger
{
    void Register(AttestationChallenge challenge);

    bool TryConsume(string challengeId);
}