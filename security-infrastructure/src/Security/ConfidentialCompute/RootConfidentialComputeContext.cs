namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class RootConfidentialComputeContext
{
    private RootConfidentialComputeContext(
        RootConfidentialComputeState state,
        RootConfidentialComputeDenialReason denialReason,
        ConfidentialPlatformClass platformClass,
        DateTimeOffset? validUntil)
    {
        State = state;
        DenialReason = denialReason;
        PlatformClass = platformClass;
        ValidUntil = validUntil;
    }

    public RootConfidentialComputeState State { get; }

    public RootConfidentialComputeDenialReason DenialReason { get; }

    public ConfidentialPlatformClass PlatformClass { get; }

    public DateTimeOffset? ValidUntil { get; }

    public bool IsSatisfied =>
        State == RootConfidentialComputeState.Satisfied;

    public static RootConfidentialComputeContext Denied(
        RootConfidentialComputeDenialReason denialReason =
            RootConfidentialComputeDenialReason.Unverified)
    {
        if (denialReason == RootConfidentialComputeDenialReason.None)
            denialReason =
                RootConfidentialComputeDenialReason.Unverified;

        return new RootConfidentialComputeContext(
            RootConfidentialComputeState.Denied,
            denialReason,
            ConfidentialPlatformClass.None,
            null);
    }
}