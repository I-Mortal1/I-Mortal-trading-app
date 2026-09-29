using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class ProgramRuntimeGateIntegrationTests
{
    private const string ProgramPath =
        @"PUBLIC_DEPLOYMENT_PATH_REMOVED";

    private const string ExpectedF23ZSha256 =
        "PUBLIC_DIGEST_REMOVED";

    [TestMethod]
    public void Program_InvokesProductionRuntimeGateWithPinnedF23Z()
    {
        var source = File.ReadAllText(ProgramPath);

        StringAssert.Contains(
            source,
            "ProductionRuntimeGate.Verify(");

        StringAssert.Contains(
            source,
            ExpectedF23ZSha256);

        StringAssert.Contains(
            source,
            "I_MORTAL_CROSS_PLATFORM_VALIDATION_GATE_V1.conf");
    }

    [TestMethod]
    public void Program_DoesNotTreatContractVerificationAsProductionAuthorization()
    {
        var source = File.ReadAllText(ProgramPath);

        StringAssert.Contains(
            source,
            "ContractVerified");

        StringAssert.Contains(
            source,
            "ProductionAuthorized");
    }

    [TestMethod]
    public void Program_DoesNotEnableProviderDispatch()
    {
        var source = File.ReadAllText(ProgramPath);

        Assert.IsFalse(
            source.Contains(
                "ProviderDispatchAllowed = true",
                StringComparison.Ordinal));

        Assert.IsFalse(
            source.Contains(
                "ProductionAuthorized = true",
                StringComparison.Ordinal));
    }
}
