using System.Security.Cryptography;

namespace IMortal.TrustBroker.Security;

public static class ProductionRuntimeGate
{
    private static readonly string[] RequiredSecuritySemantics =
    {
                "contract=I_MORTAL_CROSS_PLATFORM_VALIDATION_GATE_V1",
        "contract_version=1",
        "status=FROZEN",
        "parent_contract=I_MORTAL_HARDWARE_BOUND_CRYPTOGRAPHIC_IDENTITY_AND_PROVISIONING_V1",
        "parent_contract_sha256=PUBLIC_DIGEST_REMOVED",
        "parent_role=HARDWARE_BOUND_CRYPTOGRAPHIC_IDENTITY_AND_PROVISIONING_AUTHORITY",
        "hash_algorithm=SHA256",
        "fail_closed=true",
        "default_decision=DENY",
        "supported_platforms=WINDOWS_LINUX_MACOS_IOS",
        "production_validation_is_platform_specific=true",
        "cross_platform_validation_state_is_aggregate=true",
        "windows_hardware_validation=VALIDATED",
        "linux_hardware_validation=INCOMPLETE",
        "macos_hardware_validation=INCOMPLETE",
        "ios_hardware_validation=INCOMPLETE",
        "windows_current_gate=BLOCKED_PENDING_PRODUCTION_CONTROLS",
        "linux_current_gate=BLOCKED_PENDING_HARDWARE_VALIDATION",
        "macos_current_gate=BLOCKED_PENDING_HARDWARE_VALIDATION",
        "ios_current_gate=BLOCKED_PENDING_PHYSICAL_DEVICE_VALIDATION",
        "linux_requires_external_tpm_validation=true",
        "macos_requires_actual_secure_enclave_validation=true",
        "ios_requires_physical_device_secure_enclave_validation=true",
        "windows_validation_may_not_substitute_for_linux=true",
        "macos_validation_may_not_substitute_for_ios=true",
        "ios_validation_may_not_substitute_for_macos=true",
        "hardware_validation_required=true",
        "hardware_private_key_nonexportability_required=true",
        "database_dek_protection_validation_required=true",
        "storage_identity_validation_required=true",
        "rollback_protection_validation_required=true",
        "attestation_validation_required=true",
        "provider_boundary_validation_required=true",
        "production_attestation_required=true",
        "production_attestation_currently_resolved=false",
        "permanent_kek_requires_separate_authorization=true",
        "production_dek_requires_separate_authorization=true",
        "production_database_creation_requires_separate_authorization=true",
        "provider_dispatch_requires_separate_authorization=true",
        "live_trading_activation_requires_separate_authorization=true",
        "cross_platform_fully_validated=false",
        "production_kek_creation_allowed=false",
        "production_dek_generation_allowed=false",
        "production_database_creation_allowed=false",
        "production_database_open_allowed=false",
        "provider_operation_dispatch_allowed=false",
        "live_trading_activation_allowed=false",
        "production_authorized=false",
        "automatic_validation_promotion_allowed=false",
        "automatic_hardware_downgrade_allowed=false",
        "automatic_software_fallback_allowed=false",
        "automatic_kek_provisioning_allowed=false",
        "automatic_database_initialization_allowed=false",
        "automatic_production_authorization_allowed=false",
        "missing_evidence_action=DENY",
        "invalid_evidence_action=DENY",
        "hash_mismatch_action=DENY",
        "unknown_platform_action=DENY",
        "hardware_unavailable_action=DENY",
        "attestation_failure_action=DENY",
        "key_authority_failure_action=DENY",
        "storage_identity_failure_action=DENY",
        "rollback_validation_failure_action=DENY",
        "ai_may_override_gate=false",
        "ai_may_create_production_kek=false",
        "ai_may_generate_production_dek=false",
        "ai_may_enable_provider_dispatch=false",
        "ai_may_enable_live_trading=false",
        "ai_may_set_production_authorized=false",
        "next_linux_evidence=EXTERNAL_LINUX_TPM_FUNCTIONAL_VALIDATION",
        "next_macos_evidence=MACOS_SECURE_ENCLAVE_FUNCTIONAL_VALIDATION",
        "next_ios_evidence=PHYSICAL_IOS_SECURE_ENCLAVE_FUNCTIONAL_VALIDATION",
        "next_control=PLATFORM_VALIDATION_EVIDENCE_COLLECTION",
        "next_control_is_provisioning=false"
    };

    internal static IReadOnlyList<string> RequiredSecuritySemanticsForStartupTests =>

        Array.AsReadOnly(RequiredSecuritySemantics);

    public static ProductionRuntimeGateResult Verify(
        string contractPath,
        string expectedSha256)
    {
        try
        {
            if (!IsValidSha256(expectedSha256) ||
                string.IsNullOrWhiteSpace(contractPath) ||
                !File.Exists(contractPath))
            {
                return Denied("CONTRACT_INTEGRITY_FAILURE");
            }

            var actualHash = SHA256.HashData(
                File.ReadAllBytes(contractPath));

            var expectedHash = Convert.FromHexString(
                expectedSha256);

            if (!CryptographicOperations.FixedTimeEquals(
                    actualHash,
                    expectedHash))
            {
                return Denied("CONTRACT_INTEGRITY_FAILURE");
            }

            return VerifySemantics(
                File.ReadAllLines(contractPath),
                RequiredSecuritySemantics);
        }
        catch
        {
            return Denied("CONTRACT_VERIFICATION_FAILURE");
        }
    }

    public static ProductionRuntimeGateResult VerifyCandidateForTests(
        string contractPath,
        IEnumerable<string> requiredSemantics)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(contractPath) ||
                !File.Exists(contractPath) ||
                requiredSemantics is null)
            {
                return Denied("CONTRACT_VERIFICATION_FAILURE");
            }

            return VerifySemantics(
                File.ReadAllLines(contractPath),
                requiredSemantics);
        }
        catch
        {
            return Denied("CONTRACT_VERIFICATION_FAILURE");
        }
    }

    private static ProductionRuntimeGateResult VerifySemantics(
        IEnumerable<string> contractLines,
        IEnumerable<string> requiredSemantics)
    {
        var lines = contractLines.ToArray();

        if (lines.Any(line =>
                !string.IsNullOrWhiteSpace(line) &&
                !IsWellFormed(line)))
        {
            return Denied("CONTRACT_MALFORMED");
        }

        var nonBlank = lines
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .ToArray();

        var keys = nonBlank
            .Select(line => line.Split('=', 2)[0])
            .ToArray();

        if (keys
            .GroupBy(key => key, StringComparer.Ordinal)
            .Any(group => group.Count() != 1))
        {
            return Denied("CONTRACT_DUPLICATE_KEY");
        }

        var required = requiredSemantics.ToArray();

        if (required.Any(string.IsNullOrWhiteSpace))
        {
            return Denied("REQUIRED_SEMANTICS_INVALID");
        }

        if (!required.All(nonBlank.Contains))
        {
            return Denied("CONTRACT_SECURITY_SEMANTICS_FAILURE");
        }

        /*
         * The frozen production-gate contract is closed-world.
         * Candidate content may not add unrecognized keys or values.
         */
        if (nonBlank.Length != required.Length ||
            !nonBlank.All(required.Contains))
        {
            return Denied("CONTRACT_UNKNOWN_SEMANTIC");
        }

        /*
         * Verification of the currently frozen F23Z contract is intentionally
         * not production authorization. F23Z itself requires production denial
         * and provider-dispatch denial.
         */
        return new ProductionRuntimeGateResult(
            ContractVerified: true,
            ProductionAuthorized: false,
            ProviderDispatchAllowed: false,
            ResultCode: "CONTRACT_VERIFIED_PRODUCTION_DENIED");
    }

    private static bool IsWellFormed(string line)
    {
        var separator = line.IndexOf('=');

        return separator > 0;
    }

    private static bool IsValidSha256(string value)
    {
        return value.Length == 64 &&
            value.All(character =>
                (character >= '0' && character <= '9') ||
                (character >= 'a' && character <= 'f'));
    }

    private static ProductionRuntimeGateResult Denied(
        string resultCode) =>
        new(
            ContractVerified: false,
            ProductionAuthorized: false,
            ProviderDispatchAllowed: false,
            ResultCode: resultCode);
}

public sealed record ProductionRuntimeGateResult(
    bool ContractVerified,
    bool ProductionAuthorized,
    bool ProviderDispatchAllowed,
    string ResultCode);