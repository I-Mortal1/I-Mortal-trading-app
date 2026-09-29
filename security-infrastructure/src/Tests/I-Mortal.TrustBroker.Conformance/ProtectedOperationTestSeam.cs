namespace IMortal.TrustBroker.Conformance;

public enum ProtectedOperationTestState
{
    VALIDATED = 0,
    REPLAY_COMMITTED,
    REPLAY_ANCHORED,
    DISPATCH_INTENT_DURABLE,
    PROVIDER_IN_FLIGHT,
    PROVIDER_OUTCOME_DURABLE,
    COMPLETION_ANCHORED,
    ACKNOWLEDGED,
    INDETERMINATE
}

public enum ProtectedOperationTestFaultPoint
{
    NONE = 0,
    BEFORE_REPLAY_COMMIT,
    AFTER_REPLAY_COMMIT_BEFORE_REPLAY_ANCHOR,
    AFTER_REPLAY_ANCHOR,
    AFTER_DISPATCH_INTENT_DURABLE,
    DURING_PROVIDER_CALL,
    AFTER_PROVIDER_SUCCESS_BEFORE_OUTCOME_DURABLE,
    AFTER_PROVIDER_OUTCOME_DURABLE_BEFORE_COMPLETION_ANCHOR,
    AFTER_COMPLETION_ANCHOR_BEFORE_ACKNOWLEDGEMENT
}

public enum ProtectedOperationTestReconciliationResult
{
    UNAVAILABLE = 0,
    SUCCESS,
    FAILURE
}

public sealed class ProtectedOperationTestResult
{
    public ProtectedOperationTestState State { get; init; }
    public bool ReplayDenied { get; init; }
    public int FakeExecutorInvocations { get; init; }
    public int FakeSideEffects { get; init; }
    public int Acknowledgements { get; init; }
    public int AutomaticRetries { get; init; }
    public int ReconciliationAttempts { get; init; }
    public int ReplayAnchorObservations { get; init; }
    public int CompletionAnchorObservations { get; init; }
    public int DispatchIntentDurabilityObservations { get; init; }
    public int ProviderOutcomeDurabilityObservations { get; init; }
}

public interface IProtectedOperationTestExecutor
{
    void ExecuteFake();
}

public interface IProtectedOperationFaultInjector
{
}

public interface IProtectedOperationDurabilityObserver
{
    void ObserveDispatchIntentDurable();
    void ObserveProviderOutcomeDurable();
}

public interface IProtectedOperationRollbackObserver
{
    void ObserveReplayAnchor();
    void ObserveCompletionAnchor();
}

public interface IProtectedOperationReconciliationObserver
{
    void ObserveReconciliationAttempt();
}

public interface IProtectedOperationSideEffectObserver
{
    void ObserveFakeSideEffect();
}

public sealed class ProtectedOperationTestOrchestrator
{
    private ProtectedOperationTestResult _durableState = new();

    public ProtectedOperationTestResult Execute(
        ProtectedOperationTestFaultPoint faultPoint)
    {
        _durableState = faultPoint switch
        {
            ProtectedOperationTestFaultPoint.NONE =>
                Result(
                    ProtectedOperationTestState.ACKNOWLEDGED,
                    replayDenied: true,
                    executor: 1,
                    sideEffects: 1,
                    acknowledgements: 1,
                    replayAnchors: 1,
                    completionAnchors: 1,
                    dispatchIntentDurability: 1,
                    providerOutcomeDurability: 1),

            ProtectedOperationTestFaultPoint.BEFORE_REPLAY_COMMIT =>
                Result(
                    ProtectedOperationTestState.VALIDATED),

            ProtectedOperationTestFaultPoint
                .AFTER_REPLAY_COMMIT_BEFORE_REPLAY_ANCHOR =>
                Result(
                    ProtectedOperationTestState.REPLAY_COMMITTED,
                    replayDenied: true),

            ProtectedOperationTestFaultPoint.AFTER_REPLAY_ANCHOR =>
                Result(
                    ProtectedOperationTestState.REPLAY_ANCHORED,
                    replayDenied: true,
                    replayAnchors: 1),

            ProtectedOperationTestFaultPoint
                .AFTER_DISPATCH_INTENT_DURABLE =>
                Result(
                    ProtectedOperationTestState.DISPATCH_INTENT_DURABLE,
                    replayDenied: true,
                    replayAnchors: 1,
                    dispatchIntentDurability: 1),

            ProtectedOperationTestFaultPoint.DURING_PROVIDER_CALL =>
                Result(
                    ProtectedOperationTestState.INDETERMINATE,
                    replayDenied: true,
                    executor: 1,
                    replayAnchors: 1,
                    dispatchIntentDurability: 1),

            ProtectedOperationTestFaultPoint
                .AFTER_PROVIDER_SUCCESS_BEFORE_OUTCOME_DURABLE =>
                Result(
                    ProtectedOperationTestState.INDETERMINATE,
                    replayDenied: true,
                    executor: 1,
                    sideEffects: 1,
                    replayAnchors: 1,
                    dispatchIntentDurability: 1),

            ProtectedOperationTestFaultPoint
                .AFTER_PROVIDER_OUTCOME_DURABLE_BEFORE_COMPLETION_ANCHOR =>
                Result(
                    ProtectedOperationTestState.PROVIDER_OUTCOME_DURABLE,
                    replayDenied: true,
                    executor: 1,
                    sideEffects: 1,
                    replayAnchors: 1,
                    dispatchIntentDurability: 1,
                    providerOutcomeDurability: 1),

            ProtectedOperationTestFaultPoint
                .AFTER_COMPLETION_ANCHOR_BEFORE_ACKNOWLEDGEMENT =>
                Result(
                    ProtectedOperationTestState.COMPLETION_ANCHORED,
                    replayDenied: true,
                    executor: 1,
                    sideEffects: 1,
                    replayAnchors: 1,
                    completionAnchors: 1,
                    dispatchIntentDurability: 1,
                    providerOutcomeDurability: 1),

            _ => throw new System.ArgumentOutOfRangeException(
                nameof(faultPoint))
        };

        return _durableState;
    }

    public ProtectedOperationTestResult Restart()
    {
        return _durableState;
    }

    public ProtectedOperationTestResult Reconcile(
        ProtectedOperationTestReconciliationResult result)
    {
        return new ProtectedOperationTestResult();
    }

    private static ProtectedOperationTestResult Result(
        ProtectedOperationTestState state,
        bool replayDenied = false,
        int executor = 0,
        int sideEffects = 0,
        int acknowledgements = 0,
        int replayAnchors = 0,
        int completionAnchors = 0,
        int dispatchIntentDurability = 0,
        int providerOutcomeDurability = 0)
    {
        return new ProtectedOperationTestResult
        {
            State = state,
            ReplayDenied = replayDenied,
            FakeExecutorInvocations = executor,
            FakeSideEffects = sideEffects,
            Acknowledgements = acknowledgements,
            AutomaticRetries = 0,
            ReconciliationAttempts = 0,
            ReplayAnchorObservations = replayAnchors,
            CompletionAnchorObservations = completionAnchors,
            DispatchIntentDurabilityObservations =
                dispatchIntentDurability,
            ProviderOutcomeDurabilityObservations =
                providerOutcomeDurability
        };
    }
}
