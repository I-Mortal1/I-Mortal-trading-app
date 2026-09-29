namespace IMortal.TrustBroker.Security;

/// <summary>
/// Observable boundary for protected startup effects.
///
/// Implementations may eventually bridge to separately authorized provider,
/// hardware-key, or database operations. ProductionStartupDecision itself
/// must not perform those operations directly.
///
/// The current production state never invokes this boundary because
/// production authorization and provider dispatch remain denied.
/// </summary>
public interface IProductionStartupSideEffectObserver
{
    void ProviderOperation();

    void HardwareMutation();

    void DatabaseOpen();

    void KekCreation();

    void DekGeneration();
}

/// <summary>
/// Fail-closed production startup decision.
///
/// Contract verification is necessary but is not production authorization.
/// No protected effect is requested unless a future, separately reviewed
/// runtime state explicitly authorizes it.
/// </summary>
public static class ProductionStartupDecision
{
    public static ProductionStartupDecisionResult Evaluate(
        string contractPath,
        string expectedSha256,
        IProductionStartupSideEffectObserver observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

        var gate =
            ProductionRuntimeGate.Verify(
                contractPath,
                expectedSha256);

        return FromGate(gate);
    }

    /// <summary>
    /// Test-only candidate evaluation seam.
    ///
    /// This method cannot authorize production or provider dispatch.
    /// It delegates candidate parsing to the existing fail-closed runtime gate.
    /// </summary>
    public static ProductionStartupDecisionResult EvaluateCandidateForTests(
        string contractPath,
        IProductionStartupSideEffectObserver observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

        var gate =
            ProductionRuntimeGate.VerifyCandidateForTests(
                contractPath,
                ProductionRuntimeGate.RequiredSecuritySemanticsForStartupTests);

        return FromGate(gate);
    }

    private static ProductionStartupDecisionResult FromGate(
        ProductionRuntimeGateResult gate)
    {
        // The startup decision deliberately performs no protected side effect.
        //
        // Even a cryptographically and semantically verified contract is not
        // sufficient to authorize production. The current F23Z contract keeps
        // ProductionAuthorized and ProviderDispatchAllowed false.
        return new ProductionStartupDecisionResult(
            gate.ContractVerified,
            false,
            false,
            gate.ResultCode);
    }
}

public sealed record ProductionStartupDecisionResult(
    bool ContractVerified,
    bool ProductionAuthorized,
    bool ProviderDispatchAllowed,
    string ResultCode);
