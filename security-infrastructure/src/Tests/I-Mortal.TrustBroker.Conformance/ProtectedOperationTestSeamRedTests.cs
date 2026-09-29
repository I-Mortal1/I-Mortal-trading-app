using System;
using System.Linq;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class ProtectedOperationTestSeamRedTests
{
    private static readonly string[] RequiredTypeNames =
    {
        "IProtectedOperationTestExecutor",
        "IProtectedOperationFaultInjector",
        "IProtectedOperationDurabilityObserver",
        "IProtectedOperationRollbackObserver",
        "IProtectedOperationReconciliationObserver",
        "IProtectedOperationSideEffectObserver",
        "ProtectedOperationTestOrchestrator"
    };

    [TestMethod]
    public void RequiredTestSeamTypes_MustExist()
    {
        var assembly = typeof(ProtectedOperationTestSeamRedTests).Assembly;

        foreach (var requiredName in RequiredTypeNames)
        {
            Assert.IsTrue(
                assembly.GetTypes().Any(t => t.Name == requiredName),
                $"Missing required test seam type: {requiredName}");
        }
    }

    [TestMethod]
    public void TestExecutor_MustNotImplementITrustProvider()
    {
        var seamType = RequireType("IProtectedOperationTestExecutor");

        Assert.IsFalse(
            seamType.GetInterfaces().Any(
                i => i.FullName == "IMortal.TrustBroker.Providers.ITrustProvider"),
            "Test executor must never implement ITrustProvider.");
    }

    [TestMethod]
    public void TestOrchestrator_MustNotImplementITrustProvider()
    {
        var seamType = RequireType("ProtectedOperationTestOrchestrator");

        Assert.IsFalse(
            seamType.GetInterfaces().Any(
                i => i.FullName == "IMortal.TrustBroker.Providers.ITrustProvider"),
            "Test orchestrator must never implement ITrustProvider.");
    }

    [TestMethod]
    public void RequiredObserverInterfaces_MustActuallyBeInterfaces()
    {
        foreach (var requiredName in new[]
        {
            "IProtectedOperationTestExecutor",
            "IProtectedOperationFaultInjector",
            "IProtectedOperationDurabilityObserver",
            "IProtectedOperationRollbackObserver",
            "IProtectedOperationReconciliationObserver",
            "IProtectedOperationSideEffectObserver"
        })
        {
            Assert.IsTrue(
                RequireType(requiredName).IsInterface,
                $"{requiredName} must be an interface.");
        }
    }

    [TestMethod]
    public void TestOrchestrator_MustBeConcreteClass()
    {
        var type = RequireType("ProtectedOperationTestOrchestrator");

        Assert.IsTrue(type.IsClass);
        Assert.IsFalse(type.IsAbstract);
    }

    private static Type RequireType(string name)
    {
        var assembly = typeof(ProtectedOperationTestSeamRedTests).Assembly;

        var type = assembly
            .GetTypes()
            .SingleOrDefault(t => t.Name == name);

        Assert.IsNotNull(
            type,
            $"Required test seam type does not exist: {name}");

        return type!;
    }
}
