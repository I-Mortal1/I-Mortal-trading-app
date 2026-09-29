using IMortal.TrustBroker.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class TrustStateConformanceTests
{
    [TestMethod]
    [DataRow(TrustProviderState.Unavailable, 0)]
    [DataRow(TrustProviderState.ProviderAvailable, 1)]
    [DataRow(TrustProviderState.HardwareDetected, 2)]
    [DataRow(TrustProviderState.HardwareReady, 3)]
    [DataRow(TrustProviderState.IdentityEnrolled, 4)]
    [DataRow(TrustProviderState.UserAuthorized, 5)]
    [DataRow(TrustProviderState.ProductionAuthorized, 6)]
    public void Trust_States_Have_Stable_Numeric_Values(
        TrustProviderState state,
        int expectedValue)
    {
        Assert.AreEqual(expectedValue, (int)state);
    }

    [TestMethod]
    public void Detection_States_Precede_Identity_Enrollment()
    {
        TrustProviderState[] detectionStates =
        [
            TrustProviderState.Unavailable,
            TrustProviderState.ProviderAvailable,
            TrustProviderState.HardwareDetected,
            TrustProviderState.HardwareReady
        ];

        foreach (var state in detectionStates)
        {
            Assert.IsLessThan(
                (int)TrustProviderState.IdentityEnrolled,
                (int)state,
                $"{state} crossed the enrollment boundary.");
        }
    }

    [TestMethod]
    public void Authorization_States_Follow_Hardware_Readiness()
    {
        TrustProviderState[] authorizationStates =
        [
            TrustProviderState.IdentityEnrolled,
            TrustProviderState.UserAuthorized,
            TrustProviderState.ProductionAuthorized
        ];

        foreach (var state in authorizationStates)
        {
            Assert.IsGreaterThan(
                (int)TrustProviderState.HardwareReady,
                (int)state,
                $"{state} did not remain above the hardware-readiness boundary.");
        }
    }

    [TestMethod]
    public void Production_Authorization_Is_Highest_State()
    {
        foreach (var state in Enum.GetValues<TrustProviderState>())
        {
            if (state == TrustProviderState.ProductionAuthorized)
                continue;

            Assert.IsLessThan(
                (int)TrustProviderState.ProductionAuthorized,
                (int)state,
                $"{state} unexpectedly equals or exceeds production authorization.");
        }
    }

    [TestMethod]
    public void Trust_State_Enum_Contains_Exactly_Seven_States()
    {
        var states = Enum.GetValues<TrustProviderState>();

        Assert.HasCount(7, states);
        CollectionAssert.AllItemsAreUnique(states);
    }
}

