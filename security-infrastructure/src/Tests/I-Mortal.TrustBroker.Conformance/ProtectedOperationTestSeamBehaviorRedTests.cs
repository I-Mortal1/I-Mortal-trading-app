using System;
using System.Linq;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class ProtectedOperationTestSeamBehaviorRedTests
{
    private const string NamespaceName =
        "IMortal.TrustBroker.Conformance";

    private static Assembly AssemblyUnderTest =>
        typeof(ProtectedOperationTestOrchestrator).Assembly;

    private static Type? FindType(string name) =>
        AssemblyUnderTest.GetType(
            $"{NamespaceName}.{name}",
            throwOnError: false,
            ignoreCase: false);

    private static Type RequireType(string name)
    {
        Type? type = FindType(name);

        Assert.IsNotNull(
            type,
            $"Required behavioral seam type is absent: {name}");

        return type!;
    }

    private static string[] EnumNames(string name)
    {
        Type type = RequireType(name);

        Assert.IsTrue(
            type.IsEnum,
            $"{name} must be an enum.");

        return Enum.GetNames(type);
    }

    [TestMethod]
    public void BehavioralStateEnum_MustExist_WithRefinedTwoAnchorStates()
    {
        string[] names =
            EnumNames("ProtectedOperationTestState");

        string[] required =
        {
            "VALIDATED",
            "REPLAY_COMMITTED",
            "REPLAY_ANCHORED",
            "DISPATCH_INTENT_DURABLE",
            "PROVIDER_IN_FLIGHT",
            "PROVIDER_OUTCOME_DURABLE",
            "COMPLETION_ANCHORED",
            "ACKNOWLEDGED",
            "INDETERMINATE"
        };

        foreach (string requiredName in required)
        {
            CollectionAssert.Contains(
                names,
                requiredName,
                $"Missing state: {requiredName}");
        }

        Assert.IsFalse(
            names.Contains(
                "ROLLBACK_CHECKPOINT_ANCHORED",
                StringComparer.Ordinal),
            "Future seam must not restore the ambiguous single checkpoint state.");
    }

    [TestMethod]
    public void FaultPointEnum_MustExist_WithBothExplicitAnchorBoundaries()
    {
        string[] names =
            EnumNames("ProtectedOperationTestFaultPoint");

        string[] required =
        {
            "NONE",
            "BEFORE_REPLAY_COMMIT",
            "AFTER_REPLAY_COMMIT_BEFORE_REPLAY_ANCHOR",
            "AFTER_REPLAY_ANCHOR",
            "AFTER_DISPATCH_INTENT_DURABLE",
            "DURING_PROVIDER_CALL",
            "AFTER_PROVIDER_SUCCESS_BEFORE_OUTCOME_DURABLE",
            "AFTER_PROVIDER_OUTCOME_DURABLE_BEFORE_COMPLETION_ANCHOR",
            "AFTER_COMPLETION_ANCHOR_BEFORE_ACKNOWLEDGEMENT"
        };

        foreach (string requiredName in required)
        {
            CollectionAssert.Contains(
                names,
                requiredName,
                $"Missing fault point: {requiredName}");
        }

        Assert.IsFalse(
            names.Contains(
                "AFTER_ROLLBACK_CHECKPOINT",
                StringComparer.Ordinal),
            "Ambiguous rollback-checkpoint fault point is forbidden.");
    }

    [TestMethod]
    public void ResultType_MustExposeStateAndSecurityCounters()
    {
        Type result =
            RequireType("ProtectedOperationTestResult");

        Assert.IsTrue(
            result.IsClass || result.IsValueType,
            "ProtectedOperationTestResult must be a concrete result type.");

        string[] requiredProperties =
        {
            "State",
            "ReplayDenied",
            "FakeExecutorInvocations",
            "FakeSideEffects",
            "Acknowledgements",
            "AutomaticRetries",
            "ReconciliationAttempts",
            "ReplayAnchorObservations",
            "CompletionAnchorObservations",
            "DispatchIntentDurabilityObservations",
            "ProviderOutcomeDurabilityObservations"
        };

        foreach (string propertyName in requiredProperties)
        {
            PropertyInfo? property =
                result.GetProperty(
                    propertyName,
                    BindingFlags.Public |
                    BindingFlags.Instance);

            Assert.IsNotNull(
                property,
                $"Missing result property: {propertyName}");
        }
    }

    [TestMethod]
    public void Orchestrator_MustExposeDeterministicExecuteSeam()
    {
        Type orchestrator =
            typeof(ProtectedOperationTestOrchestrator);

        Type faultType =
            RequireType("ProtectedOperationTestFaultPoint");

        Type resultType =
            RequireType("ProtectedOperationTestResult");

        MethodInfo? execute =
            orchestrator.GetMethod(
                "Execute",
                BindingFlags.Public |
                BindingFlags.Instance,
                binder: null,
                types: new[] { faultType },
                modifiers: null);

        Assert.IsNotNull(
            execute,
            "Execute(ProtectedOperationTestFaultPoint) is required.");

        Assert.AreEqual(
            resultType,
            execute!.ReturnType,
            "Execute must return ProtectedOperationTestResult.");
    }

    [TestMethod]
    public void Orchestrator_MustExposeInMemoryRestartWithoutAutomaticDispatch()
    {
        Type orchestrator =
            typeof(ProtectedOperationTestOrchestrator);

        Type resultType =
            RequireType("ProtectedOperationTestResult");

        MethodInfo? restart =
            orchestrator.GetMethod(
                "Restart",
                BindingFlags.Public |
                BindingFlags.Instance,
                binder: null,
                types: Type.EmptyTypes,
                modifiers: null);

        Assert.IsNotNull(
            restart,
            "Restart() is required for deterministic in-memory recovery simulation.");

        Assert.AreEqual(
            resultType,
            restart!.ReturnType,
            "Restart must return ProtectedOperationTestResult.");
    }

    [TestMethod]
    public void Orchestrator_MustExposeExplicitReconciliation()
    {
        Type orchestrator =
            typeof(ProtectedOperationTestOrchestrator);

        Type resultType =
            RequireType("ProtectedOperationTestResult");

        Type reconciliationType =
            RequireType("ProtectedOperationTestReconciliationResult");

        Assert.IsTrue(
            reconciliationType.IsEnum,
            "ProtectedOperationTestReconciliationResult must be an enum.");

        string[] names =
            Enum.GetNames(reconciliationType);

        CollectionAssert.Contains(names, "UNAVAILABLE");
        CollectionAssert.Contains(names, "SUCCESS");
        CollectionAssert.Contains(names, "FAILURE");

        MethodInfo? reconcile =
            orchestrator.GetMethod(
                "Reconcile",
                BindingFlags.Public |
                BindingFlags.Instance,
                binder: null,
                types: new[] { reconciliationType },
                modifiers: null);

        Assert.IsNotNull(
            reconcile,
            "Reconcile(ProtectedOperationTestReconciliationResult) is required.");

        Assert.AreEqual(
            resultType,
            reconcile!.ReturnType,
            "Reconcile must return ProtectedOperationTestResult.");
    }

    [TestMethod]
    public void ObserverInterfaces_MustExposeDistinctReplayAndCompletionAnchors()
    {
        Type rollbackObserver =
            typeof(IProtectedOperationRollbackObserver);

        MethodInfo? replayAnchor =
            rollbackObserver.GetMethod(
                "ObserveReplayAnchor",
                BindingFlags.Public |
                BindingFlags.Instance);

        MethodInfo? completionAnchor =
            rollbackObserver.GetMethod(
                "ObserveCompletionAnchor",
                BindingFlags.Public |
                BindingFlags.Instance);

        Assert.IsNotNull(
            replayAnchor,
            "Rollback observer must distinguish replay anchoring.");

        Assert.IsNotNull(
            completionAnchor,
            "Rollback observer must distinguish completion anchoring.");

        Assert.AreEqual(
            typeof(void),
            replayAnchor!.ReturnType);

        Assert.AreEqual(
            typeof(void),
            completionAnchor!.ReturnType);
    }

    [TestMethod]
    public void DurabilityObserver_MustDistinguishDispatchIntentAndProviderOutcome()
    {
        Type observer =
            typeof(IProtectedOperationDurabilityObserver);

        MethodInfo? dispatchIntent =
            observer.GetMethod(
                "ObserveDispatchIntentDurable",
                BindingFlags.Public |
                BindingFlags.Instance);

        MethodInfo? providerOutcome =
            observer.GetMethod(
                "ObserveProviderOutcomeDurable",
                BindingFlags.Public |
                BindingFlags.Instance);

        Assert.IsNotNull(
            dispatchIntent,
            "Dispatch-intent durability observation is required.");

        Assert.IsNotNull(
            providerOutcome,
            "Provider-outcome durability observation is required.");

        Assert.AreEqual(
            typeof(void),
            dispatchIntent!.ReturnType);

        Assert.AreEqual(
            typeof(void),
            providerOutcome!.ReturnType);
    }

    [TestMethod]
    public void TestExecutor_MustExposeFakeExecutionOnly()
    {
        Type executor =
            typeof(IProtectedOperationTestExecutor);

        MethodInfo? execute =
            executor.GetMethod(
                "ExecuteFake",
                BindingFlags.Public |
                BindingFlags.Instance);

        Assert.IsNotNull(
            execute,
            "IProtectedOperationTestExecutor.ExecuteFake() is required.");

        Assert.AreEqual(
            typeof(void),
            execute!.ReturnType);
    }

    [TestMethod]
    public void SideEffectObserver_MustExposeFakeSideEffectObservation()
    {
        Type observer =
            typeof(IProtectedOperationSideEffectObserver);

        MethodInfo? method =
            observer.GetMethod(
                "ObserveFakeSideEffect",
                BindingFlags.Public |
                BindingFlags.Instance);

        Assert.IsNotNull(
            method,
            "Fake side-effect observation is required.");

        Assert.AreEqual(
            typeof(void),
            method!.ReturnType);
    }

    [TestMethod]
    public void ReconciliationObserver_MustExposeAttemptObservation()
    {
        Type observer =
            typeof(IProtectedOperationReconciliationObserver);

        MethodInfo? method =
            observer.GetMethod(
                "ObserveReconciliationAttempt",
                BindingFlags.Public |
                BindingFlags.Instance);

        Assert.IsNotNull(
            method,
            "Reconciliation-attempt observation is required.");

        Assert.AreEqual(
            typeof(void),
            method!.ReturnType);
    }
}
