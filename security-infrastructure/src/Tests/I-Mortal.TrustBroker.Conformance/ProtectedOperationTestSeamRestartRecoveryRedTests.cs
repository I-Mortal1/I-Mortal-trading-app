using Microsoft.VisualStudio.TestTools.UnitTesting;
namespace IMortal.TrustBroker.Conformance;

[TestClass]

public sealed class ProtectedOperationTestSeamRestartRecoveryRedTests
{
    [TestMethod]
    public void RestartWithoutPriorExecute_FailsClosed()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var result = orchestrator.Restart();

        Assert.AreEqual(ProtectedOperationTestState.VALIDATED, result.State);
        Assert.IsFalse(result.ReplayDenied);
        Assert.AreEqual(0, result.FakeExecutorInvocations);
        Assert.AreEqual(0, result.FakeSideEffects);
        Assert.AreEqual(0, result.Acknowledgements);
        Assert.AreEqual(0, result.AutomaticRetries);
        Assert.AreEqual(0, result.ReconciliationAttempts);
        Assert.AreEqual(0, result.ReplayAnchorObservations);
        Assert.AreEqual(0, result.CompletionAnchorObservations);
        Assert.AreEqual(0, result.DispatchIntentDurabilityObservations);
        Assert.AreEqual(0, result.ProviderOutcomeDurabilityObservations);
    }

    [TestMethod]
    public void RestartFromValidated_PreservesValidatedWithoutReplayConsumption()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var before = orchestrator.Execute(
            ProtectedOperationTestFaultPoint.BEFORE_REPLAY_COMMIT);

        var after = orchestrator.Restart();

        Assert.AreEqual(ProtectedOperationTestState.VALIDATED, before.State);
        Assert.AreEqual(before.State, after.State);
        Assert.AreEqual(before.ReplayDenied, after.ReplayDenied);
        AssertCountersEqual(before, after);
    }

    [TestMethod]
    public void RestartFromReplayCommitted_PreservesReplayDenialWithoutDispatch()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var before = orchestrator.Execute(
            ProtectedOperationTestFaultPoint
                .AFTER_REPLAY_COMMIT_BEFORE_REPLAY_ANCHOR);

        var after = orchestrator.Restart();

        Assert.AreEqual(ProtectedOperationTestState.REPLAY_COMMITTED, after.State);
        Assert.IsTrue(after.ReplayDenied);
        Assert.AreEqual(0, after.FakeExecutorInvocations);
        Assert.AreEqual(0, after.FakeSideEffects);
        Assert.AreEqual(0, after.Acknowledgements);
        Assert.AreEqual(0, after.AutomaticRetries);
        AssertCountersEqual(before, after);
    }

    [TestMethod]
    public void RestartFromReplayAnchored_PreservesReplayDenialWithoutDispatch()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var before = orchestrator.Execute(
            ProtectedOperationTestFaultPoint.AFTER_REPLAY_ANCHOR);

        var after = orchestrator.Restart();

        Assert.AreEqual(ProtectedOperationTestState.REPLAY_ANCHORED, after.State);
        Assert.IsTrue(after.ReplayDenied);
        Assert.AreEqual(0, after.FakeExecutorInvocations);
        Assert.AreEqual(0, after.FakeSideEffects);
        Assert.AreEqual(0, after.Acknowledgements);
        Assert.AreEqual(0, after.AutomaticRetries);
        AssertCountersEqual(before, after);
    }

    [TestMethod]
    public void RestartFromDispatchIntent_DoesNotAutoDispatch()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var before = orchestrator.Execute(
            ProtectedOperationTestFaultPoint.AFTER_DISPATCH_INTENT_DURABLE);

        var after = orchestrator.Restart();

        Assert.AreEqual(
            ProtectedOperationTestState.DISPATCH_INTENT_DURABLE,
            after.State);

        Assert.IsTrue(after.ReplayDenied);
        Assert.AreEqual(0, after.FakeExecutorInvocations);
        Assert.AreEqual(0, after.FakeSideEffects);
        Assert.AreEqual(0, after.Acknowledgements);
        Assert.AreEqual(0, after.AutomaticRetries);
        AssertCountersEqual(before, after);
    }

    [TestMethod]
    public void RestartFromDuringProviderCall_RemainsIndeterminateWithoutRetry()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var before = orchestrator.Execute(
            ProtectedOperationTestFaultPoint.DURING_PROVIDER_CALL);

        var after = orchestrator.Restart();

        Assert.AreEqual(ProtectedOperationTestState.INDETERMINATE, after.State);
        Assert.IsTrue(after.ReplayDenied);
        Assert.AreEqual(1, after.FakeExecutorInvocations);
        Assert.AreEqual(0, after.Acknowledgements);
        Assert.AreEqual(0, after.AutomaticRetries);
        AssertCountersEqual(before, after);
    }

    [TestMethod]
    public void RestartFromProviderSuccessBeforeOutcome_RemainsIndeterminateWithoutRetry()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var before = orchestrator.Execute(
            ProtectedOperationTestFaultPoint
                .AFTER_PROVIDER_SUCCESS_BEFORE_OUTCOME_DURABLE);

        var after = orchestrator.Restart();

        Assert.AreEqual(ProtectedOperationTestState.INDETERMINATE, after.State);
        Assert.IsTrue(after.ReplayDenied);
        Assert.AreEqual(1, after.FakeExecutorInvocations);
        Assert.AreEqual(1, after.FakeSideEffects);
        Assert.AreEqual(0, after.Acknowledgements);
        Assert.AreEqual(0, after.AutomaticRetries);
        AssertCountersEqual(before, after);
    }

    [TestMethod]
    public void RestartFromProviderOutcome_PreservesOutcomeWithoutCompletionOrAck()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var before = orchestrator.Execute(
            ProtectedOperationTestFaultPoint
                .AFTER_PROVIDER_OUTCOME_DURABLE_BEFORE_COMPLETION_ANCHOR);

        var after = orchestrator.Restart();

        Assert.AreEqual(
            ProtectedOperationTestState.PROVIDER_OUTCOME_DURABLE,
            after.State);

        Assert.IsTrue(after.ReplayDenied);
        Assert.AreEqual(1, after.FakeExecutorInvocations);
        Assert.AreEqual(1, after.FakeSideEffects);
        Assert.AreEqual(0, after.CompletionAnchorObservations);
        Assert.AreEqual(0, after.Acknowledgements);
        Assert.AreEqual(0, after.AutomaticRetries);
        AssertCountersEqual(before, after);
    }

    [TestMethod]
    public void RestartFromCompletionAnchor_PreservesCompletionWithoutRepeatProviderOrAck()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var before = orchestrator.Execute(
            ProtectedOperationTestFaultPoint
                .AFTER_COMPLETION_ANCHOR_BEFORE_ACKNOWLEDGEMENT);

        var after = orchestrator.Restart();

        Assert.AreEqual(
            ProtectedOperationTestState.COMPLETION_ANCHORED,
            after.State);

        Assert.IsTrue(after.ReplayDenied);
        Assert.AreEqual(1, after.FakeExecutorInvocations);
        Assert.AreEqual(1, after.FakeSideEffects);
        Assert.AreEqual(1, after.CompletionAnchorObservations);
        Assert.AreEqual(0, after.Acknowledgements);
        Assert.AreEqual(0, after.AutomaticRetries);
        AssertCountersEqual(before, after);
    }

    [TestMethod]
    public void RestartFromAcknowledged_PreservesAcknowledgedWithoutRepeatProvider()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var before = orchestrator.Execute(
            ProtectedOperationTestFaultPoint.NONE);

        var after = orchestrator.Restart();

        Assert.AreEqual(ProtectedOperationTestState.ACKNOWLEDGED, after.State);
        Assert.IsTrue(after.ReplayDenied);
        Assert.AreEqual(1, after.FakeExecutorInvocations);
        Assert.AreEqual(1, after.FakeSideEffects);
        Assert.AreEqual(1, after.Acknowledgements);
        Assert.AreEqual(0, after.AutomaticRetries);
        AssertCountersEqual(before, after);
    }

    [TestMethod]
    public void RestartPreservesAllCountersWithoutIncrement()
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();

        var before = orchestrator.Execute(
            ProtectedOperationTestFaultPoint.NONE);

        var after = orchestrator.Restart();

        AssertCountersEqual(before, after);
    }

    private static void AssertCountersEqual(
        ProtectedOperationTestResult before,
        ProtectedOperationTestResult after)
    {
        Assert.AreEqual(
            before.FakeExecutorInvocations,
            after.FakeExecutorInvocations);

        Assert.AreEqual(
            before.FakeSideEffects,
            after.FakeSideEffects);

        Assert.AreEqual(
            before.Acknowledgements,
            after.Acknowledgements);

        Assert.AreEqual(
            before.AutomaticRetries,
            after.AutomaticRetries);

        Assert.AreEqual(
            before.ReconciliationAttempts,
            after.ReconciliationAttempts);

        Assert.AreEqual(
            before.ReplayAnchorObservations,
            after.ReplayAnchorObservations);

        Assert.AreEqual(
            before.CompletionAnchorObservations,
            after.CompletionAnchorObservations);

        Assert.AreEqual(
            before.DispatchIntentDurabilityObservations,
            after.DispatchIntentDurabilityObservations);

        Assert.AreEqual(
            before.ProviderOutcomeDurabilityObservations,
            after.ProviderOutcomeDurabilityObservations);
    }
}
