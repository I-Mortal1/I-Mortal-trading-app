using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class ProtectedOperationTestSeamCoreBehaviorRedTests
{
    private static ProtectedOperationTestResult Execute(
        ProtectedOperationTestFaultPoint fault)
    {
        var orchestrator = new ProtectedOperationTestOrchestrator();
        return orchestrator.Execute(fault);
    }

    private static void AssertCommonNoRetry(
        ProtectedOperationTestResult result)
    {
        Assert.AreEqual(0, result.AutomaticRetries);
    }

    [TestMethod]
    public void None_CompletesFullFakePath_AndAcknowledges()
    {
        var result = Execute(ProtectedOperationTestFaultPoint.NONE);

        Assert.AreEqual(
            ProtectedOperationTestState.ACKNOWLEDGED,
            result.State);

        Assert.IsTrue(result.ReplayDenied);
        Assert.AreEqual(1, result.FakeExecutorInvocations);
        Assert.AreEqual(1, result.FakeSideEffects);
        Assert.AreEqual(1, result.Acknowledgements);
        Assert.AreEqual(0, result.AutomaticRetries);
        Assert.AreEqual(0, result.ReconciliationAttempts);
        Assert.AreEqual(1, result.ReplayAnchorObservations);
        Assert.AreEqual(1, result.CompletionAnchorObservations);
        Assert.AreEqual(1, result.DispatchIntentDurabilityObservations);
        Assert.AreEqual(1, result.ProviderOutcomeDurabilityObservations);
    }

    [TestMethod]
    public void BeforeReplayCommit_StopsValidated_WithoutConsumingReplay()
    {
        var result =
            Execute(ProtectedOperationTestFaultPoint.BEFORE_REPLAY_COMMIT);

        Assert.AreEqual(
            ProtectedOperationTestState.VALIDATED,
            result.State);

        Assert.IsFalse(result.ReplayDenied);
        Assert.AreEqual(0, result.FakeExecutorInvocations);
        Assert.AreEqual(0, result.FakeSideEffects);
        Assert.AreEqual(0, result.Acknowledgements);
        Assert.AreEqual(0, result.ReplayAnchorObservations);
        Assert.AreEqual(0, result.CompletionAnchorObservations);
        AssertCommonNoRetry(result);
    }

    [TestMethod]
    public void AfterReplayCommitBeforeAnchor_PreservesReplayDenial_NoProviderCall()
    {
        var result =
            Execute(
                ProtectedOperationTestFaultPoint
                    .AFTER_REPLAY_COMMIT_BEFORE_REPLAY_ANCHOR);

        Assert.AreEqual(
            ProtectedOperationTestState.REPLAY_COMMITTED,
            result.State);

        Assert.IsTrue(result.ReplayDenied);
        Assert.AreEqual(0, result.FakeExecutorInvocations);
        Assert.AreEqual(0, result.FakeSideEffects);
        Assert.AreEqual(0, result.Acknowledgements);
        Assert.AreEqual(0, result.ReplayAnchorObservations);
        Assert.AreEqual(0, result.CompletionAnchorObservations);
        AssertCommonNoRetry(result);
    }

    [TestMethod]
    public void AfterReplayAnchor_StopsBeforeDispatchIntent_NoProviderCall()
    {
        var result =
            Execute(
                ProtectedOperationTestFaultPoint.AFTER_REPLAY_ANCHOR);

        Assert.AreEqual(
            ProtectedOperationTestState.REPLAY_ANCHORED,
            result.State);

        Assert.IsTrue(result.ReplayDenied);
        Assert.AreEqual(0, result.FakeExecutorInvocations);
        Assert.AreEqual(0, result.FakeSideEffects);
        Assert.AreEqual(0, result.Acknowledgements);
        Assert.AreEqual(1, result.ReplayAnchorObservations);
        Assert.AreEqual(0, result.CompletionAnchorObservations);
        Assert.AreEqual(
            0,
            result.DispatchIntentDurabilityObservations);

        AssertCommonNoRetry(result);
    }

    [TestMethod]
    public void AfterDispatchIntent_StopsBeforeProviderCall()
    {
        var result =
            Execute(
                ProtectedOperationTestFaultPoint
                    .AFTER_DISPATCH_INTENT_DURABLE);

        Assert.AreEqual(
            ProtectedOperationTestState.DISPATCH_INTENT_DURABLE,
            result.State);

        Assert.IsTrue(result.ReplayDenied);
        Assert.AreEqual(0, result.FakeExecutorInvocations);
        Assert.AreEqual(0, result.FakeSideEffects);
        Assert.AreEqual(0, result.Acknowledgements);
        Assert.AreEqual(
            1,
            result.DispatchIntentDurabilityObservations);
        Assert.AreEqual(
            0,
            result.ProviderOutcomeDurabilityObservations);

        AssertCommonNoRetry(result);
    }

    [TestMethod]
    public void DuringProviderCall_BecomesIndeterminate_AndNeverAcknowledges()
    {
        var result =
            Execute(
                ProtectedOperationTestFaultPoint.DURING_PROVIDER_CALL);

        Assert.AreEqual(
            ProtectedOperationTestState.INDETERMINATE,
            result.State);

        Assert.IsTrue(result.ReplayDenied);
        Assert.AreEqual(1, result.FakeExecutorInvocations);
        Assert.AreEqual(0, result.Acknowledgements);
        Assert.AreEqual(0, result.AutomaticRetries);

        // Deliberately do not assert FakeSideEffects here.
        // F25K explicitly states that this fake count is not
        // security-authoritative at this crash boundary.
    }

    [TestMethod]
    public void AfterProviderSuccessBeforeOutcomeDurable_BecomesIndeterminate()
    {
        var result =
            Execute(
                ProtectedOperationTestFaultPoint
                    .AFTER_PROVIDER_SUCCESS_BEFORE_OUTCOME_DURABLE);

        Assert.AreEqual(
            ProtectedOperationTestState.INDETERMINATE,
            result.State);

        Assert.IsTrue(result.ReplayDenied);
        Assert.AreEqual(1, result.FakeExecutorInvocations);
        Assert.AreEqual(1, result.FakeSideEffects);
        Assert.AreEqual(0, result.Acknowledgements);
        Assert.AreEqual(0, result.AutomaticRetries);
        Assert.AreEqual(
            0,
            result.ProviderOutcomeDurabilityObservations);
    }

    [TestMethod]
    public void AfterProviderOutcomeBeforeCompletionAnchor_NoAcknowledgement()
    {
        var result =
            Execute(
                ProtectedOperationTestFaultPoint
                    .AFTER_PROVIDER_OUTCOME_DURABLE_BEFORE_COMPLETION_ANCHOR);

        Assert.AreEqual(
            ProtectedOperationTestState.PROVIDER_OUTCOME_DURABLE,
            result.State);

        Assert.IsTrue(result.ReplayDenied);
        Assert.AreEqual(1, result.FakeExecutorInvocations);
        Assert.AreEqual(1, result.FakeSideEffects);
        Assert.AreEqual(0, result.Acknowledgements);
        Assert.AreEqual(
            1,
            result.ProviderOutcomeDurabilityObservations);
        Assert.AreEqual(
            0,
            result.CompletionAnchorObservations);

        AssertCommonNoRetry(result);
    }

    [TestMethod]
    public void AfterCompletionAnchorBeforeAck_NoRepeatProvider_AndNoAckYet()
    {
        var result =
            Execute(
                ProtectedOperationTestFaultPoint
                    .AFTER_COMPLETION_ANCHOR_BEFORE_ACKNOWLEDGEMENT);

        Assert.AreEqual(
            ProtectedOperationTestState.COMPLETION_ANCHORED,
            result.State);

        Assert.IsTrue(result.ReplayDenied);
        Assert.AreEqual(1, result.FakeExecutorInvocations);
        Assert.AreEqual(1, result.FakeSideEffects);
        Assert.AreEqual(0, result.Acknowledgements);
        Assert.AreEqual(1, result.CompletionAnchorObservations);
        AssertCommonNoRetry(result);
    }
}
