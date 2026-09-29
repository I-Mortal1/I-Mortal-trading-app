namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public enum ProtectedStateRecoveryDisposition
{
    Deny = 0,
    NoTransaction = 1,
    RecoverLastVerifiedDurableState = 2,
    CompleteVerifiedDurableTransaction = 3,
    AcceptVerifiedCommittedState = 4
}