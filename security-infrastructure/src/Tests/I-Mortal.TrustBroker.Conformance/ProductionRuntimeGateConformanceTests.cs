using IMortal.TrustBroker.Security;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class ProductionRuntimeGateConformanceTests
{
    private const string ExpectedSha256 =
        "PUBLIC_DIGEST_REMOVED";

    private static readonly string[] ValidContract =
    {
        "contract=I_MORTAL_CROSS_PLATFORM_VALIDATION_GATE_V1",
        "contract_version=1",
        "status=FROZEN",
        "hash_algorithm=SHA256",
        "fail_closed=true",
        "default_decision=DENY",
        "windows_hardware_validation=VALIDATED",
        "linux_hardware_validation=INCOMPLETE",
        "macos_hardware_validation=INCOMPLETE",
        "ios_hardware_validation=INCOMPLETE",
        "production_attestation_currently_resolved=false",
        "cross_platform_fully_validated=false",
        "production_kek_creation_allowed=false",
        "production_dek_generation_allowed=false",
        "production_database_creation_allowed=false",
        "production_database_open_allowed=false",
        "provider_operation_dispatch_allowed=false",
        "live_trading_activation_allowed=false",
        "production_authorized=false",
        "automatic_validation_promotion_allowed=false",
        "automatic_software_fallback_allowed=false",
        "automatic_production_authorization_allowed=false",
        "missing_evidence_action=DENY",
        "invalid_evidence_action=DENY",
        "hash_mismatch_action=DENY",
        "hardware_unavailable_action=DENY",
        "attestation_failure_action=DENY",
        "ai_may_override_gate=false",
        "ai_may_set_production_authorized=false"
    };

    private static string TempFile(IEnumerable<string> lines)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"i-mortal-f24d-{Guid.NewGuid():N}.conf");

        File.WriteAllText(
            path,
            string.Join("\n", lines) + "\n",
            new System.Text.UTF8Encoding(false));

        return path;
    }

    [TestMethod]
    public void MissingContract_IsDenied()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"i-mortal-missing-{Guid.NewGuid():N}.conf");

        var result = ProductionRuntimeGate.Verify(path, ExpectedSha256);

        Assert.IsFalse(result.ContractVerified);
        Assert.IsFalse(result.ProductionAuthorized);
        Assert.IsFalse(result.ProviderDispatchAllowed);
    }

    [TestMethod]
    public void WrongExpectedHash_IsDenied()
    {
        var path = TempFile(ValidContract);

        try
        {
            var result = ProductionRuntimeGate.Verify(
                path,
                new string('0', 64));

            Assert.IsFalse(result.ContractVerified);
            Assert.IsFalse(result.ProductionAuthorized);
            Assert.IsFalse(result.ProviderDispatchAllowed);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void MalformedContract_IsDenied()
    {
        var path = TempFile(
            ValidContract.Append("MALFORMED_LINE"));

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsFalse(result.ContractVerified);
            Assert.IsFalse(result.ProductionAuthorized);
            Assert.IsFalse(result.ProviderDispatchAllowed);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void DuplicateKey_IsDenied()
    {
        var path = TempFile(
            ValidContract.Append("production_authorized=false"));

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsFalse(result.ContractVerified);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void MissingRequiredKey_IsDenied()
    {
        var candidate = ValidContract
            .Where(x => x != "production_authorized=false")
            .ToArray();

        var path = TempFile(candidate);

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsFalse(result.ContractVerified);
            Assert.IsFalse(result.ProductionAuthorized);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void AlteredSecuritySemantic_IsDenied()
    {
        var candidate = ValidContract
            .Select(x => x == "production_authorized=false"
                ? "production_authorized=true"
                : x)
            .ToArray();

        var path = TempFile(candidate);

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsFalse(result.ContractVerified);
            Assert.IsFalse(result.ProductionAuthorized);
            Assert.IsFalse(result.ProviderDispatchAllowed);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void ProviderDispatchSelfEnable_IsDenied()
    {
        var candidate = ValidContract
            .Select(x => x == "provider_operation_dispatch_allowed=false"
                ? "provider_operation_dispatch_allowed=true"
                : x)
            .ToArray();

        var path = TempFile(candidate);

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsFalse(result.ContractVerified);
            Assert.IsFalse(result.ProviderDispatchAllowed);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void AutomaticPromotionSelfEnable_IsDenied()
    {
        var candidate = ValidContract
            .Select(x => x == "automatic_production_authorization_allowed=false"
                ? "automatic_production_authorization_allowed=true"
                : x)
            .ToArray();

        var path = TempFile(candidate);

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsFalse(result.ContractVerified);
            Assert.IsFalse(result.ProductionAuthorized);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void AiOverrideSelfEnable_IsDenied()
    {
        var candidate = ValidContract
            .Select(x => x == "ai_may_override_gate=false"
                ? "ai_may_override_gate=true"
                : x)
            .ToArray();

        var path = TempFile(candidate);

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsFalse(result.ContractVerified);
            Assert.IsFalse(result.ProductionAuthorized);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void SemanticallyValidCandidate_IsVerificationOnly()
    {
        var path = TempFile(ValidContract);

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsTrue(result.ContractVerified);
            Assert.IsFalse(result.ProductionAuthorized);
            Assert.IsFalse(result.ProviderDispatchAllowed);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void ValidCandidate_StillDeniesProduction()
    {
        var path = TempFile(ValidContract);

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsFalse(result.ProductionAuthorized);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void ValidCandidate_StillDeniesProviderDispatch()
    {
        var path = TempFile(ValidContract);

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsFalse(result.ProviderDispatchAllowed);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void UnknownContractKey_IsDenied()
    {
        var candidate = ValidContract
            .Append("unexpected_security_switch=false")
            .ToArray();

        var path = TempFile(candidate);

        try
        {
            var result = ProductionRuntimeGate.VerifyCandidateForTests(
                path,
                ValidContract);

            Assert.IsFalse(result.ContractVerified);
            Assert.IsFalse(result.ProductionAuthorized);
            Assert.IsFalse(result.ProviderDispatchAllowed);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void AuthoritativeF23Z_VerifiesButRemainsDenied()
    {
        const string expectedSha256 =
            "PUBLIC_DIGEST_REMOVED";

        const string contractPath =
            @"PUBLIC_DEPLOYMENT_PATH_REMOVED";

        var result = ProductionRuntimeGate.Verify(
            contractPath,
            expectedSha256);

        Assert.IsTrue(result.ContractVerified);
        Assert.IsFalse(result.ProductionAuthorized);
        Assert.IsFalse(result.ProviderDispatchAllowed);
    }
}