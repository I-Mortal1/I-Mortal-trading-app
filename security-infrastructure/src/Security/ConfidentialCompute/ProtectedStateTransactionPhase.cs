namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public enum ProtectedStateTransactionPhase
{
    None = 0,
    IntentPrepared = 1,
    IntentDurable = 2,
    StateAndReplayPrepared = 3,
    StateAndReplayDurable = 4,
    CommitMarkerDurable = 5
}