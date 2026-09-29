namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed record RootConfidentialComputeGateResult(
    RootConfidentialComputeState State,
    RootConfidentialComputeDenialReason DenialReason,
    ConfidentialPlatformClass PlatformClass,
    DateTimeOffset? ValidUntil)
{
    public bool IsSatisfied =>
        State == RootConfidentialComputeState.Satisfied;
}
