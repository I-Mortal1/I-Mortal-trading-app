using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace IMortal.TrustBroker;

internal static class Program
{
    private static readonly bool ProductionAuthorized = false;

    private const string RootPath = @"PUBLIC_DEPLOYMENT_PATH_REMOVED";
    private const string ProductionGateContractPath =
        RootPath + @"\security-spec\I_MORTAL_CROSS_PLATFORM_VALIDATION_GATE_V1.conf";

    private const string ProductionGateContractSha256 =
        "PUBLIC_DIGEST_REMOVED";
    private const string PolicyPath = RootPath + @"\broker-policy-v1.conf";
    private const string PolicyIntegrityPath = PolicyPath + ".sha256";
    private const string RequestContractPath = RootPath + @"\request-contract-v1.conf";
    private const string RequestContractIntegrityPath = RequestContractPath + ".sha256";

    public static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--detect")
            return RunDetection();

        if (!VerifyPolicyIntegrity())
            return 78;

        if (!VerifyPolicySemantics())
            return 79;

        if (!VerifyRequestContract())
            return 80;

        var productionGate = IMortal.TrustBroker.Security.ProductionRuntimeGate.Verify(
            ProductionGateContractPath,
            ProductionGateContractSha256);

        if (!productionGate.ContractVerified)
            return 82;

        if (productionGate.ProductionAuthorized && !ProductionAuthorized)
            return 83;

        if (productionGate.ProviderDispatchAllowed)
            return 84;

        if (!ProductionAuthorized)
            return 77;

        return 1;
    }

    private static bool VerifyPolicyIntegrity()
    {
        try
        {
            if (!File.Exists(PolicyPath) || !File.Exists(PolicyIntegrityPath))
                return false;

            var expected = File.ReadAllText(PolicyIntegrityPath).Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[0];
            if (expected.Length != 64 || !expected.All(Uri.IsHexDigit))
                return false;

            var actual = Convert.ToHexString(
                SHA256.HashData(File.ReadAllBytes(PolicyPath)));

            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(actual),
                Convert.FromHexString(expected));
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyPolicySemantics()
    {
        try
        {
            var policy = File.ReadAllLines(PolicyPath);

            var required = new[]
            {
                "default_access=DENY",
                "fail_closed=true",
                "tpm_required=true",
                "verified_user_authorization_required=true",
                "explicit_operation_scope_required=true",
                "capability_replay_allowed=false",
                "raw_master_key_export_allowed=false",
                "raw_private_key_export_allowed=false",
                "wsl_direct_tpm_authority=false",
                "i_mortal_direct_tpm_authority=false",
                "ai_direct_tpm_authority=false",
                "production_authorized=false"
            };

            return required.All(policy.Contains);
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyRequestContract()
    {
        try
        {
            if (!File.Exists(RequestContractPath) ||
                !File.Exists(RequestContractIntegrityPath))
                return false;

            var expected = File.ReadAllText(RequestContractIntegrityPath).Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[0];
            if (expected.Length != 64 || !expected.All(Uri.IsHexDigit))
                return false;

            var actual = Convert.ToHexString(
                SHA256.HashData(File.ReadAllBytes(RequestContractPath)));

            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(actual),
                    Convert.FromHexString(expected)))
                return false;

            var contract = File.ReadAllLines(RequestContractPath);

            var required = new[]
            {
                "contract=I-MORTAL-BYOTR-REQUEST-V1",
                "default=DENY",
                "fail_closed=true",
                "production_authorized=false",
                "request_id_required=true",
                "operation_required=true",
                "device_identity_required=true",
                "nonce_required=true",
                "expiration_required=true",
                "policy_version_required=true",
                "authorization_state_required=true",
                "request_id_unique_required=true",
                "nonce_unique_required=true",
                "expired_request_allowed=false",
                "replayed_request_allowed=false",
                "operation_binding_required=true",
                "device_binding_required=true",
                "policy_binding_required=true",
                "authorization_state_verified_required=true",
                "authorization_scope_exact_match_required=true",
                "request_scope_escalation_allowed=false",
                "arbitrary_operation_allowed=false",
                "operation_raw_tpm_command_allowed=false",
                "master_key_output_allowed=false",
                "private_key_output_allowed=false",
                "credential_output_allowed=false",
                "secret_output_allowed=false",
                "protected_source_output_allowed=false",
                "ai_readable_secret_output_allowed=false",
                "response_minimization_required=true",
                "protected_material_in_response_allowed=false",
                "protected_material_in_error_allowed=false",
                "protected_material_in_log_allowed=false"
            };

            return required.All(contract.Contains);
        }
        catch
        {
            return false;
        }
    }
    private static int RunDetection()
    {
        try
        {
            var provider = Providers.TrustProviderFactory.Create();
            var result = provider.Detect();

            Console.WriteLine($"provider_id={result.ProviderId}");
            Console.WriteLine($"provider_available={provider.IsAvailable().ToString().ToLowerInvariant()}");
            Console.WriteLine($"hardware_detected={(result.State >= Providers.TrustProviderState.HardwareDetected).ToString().ToLowerInvariant()}");
            Console.WriteLine($"hardware_ready={(result.State >= Providers.TrustProviderState.HardwareReady).ToString().ToLowerInvariant()}");
            Console.WriteLine($"hardware_backed={result.HardwareBacked.ToString().ToLowerInvariant()}");
            Console.WriteLine($"non_exportable_keys_supported={result.NonExportableKeysSupported.ToString().ToLowerInvariant()}");

            return 0;
        }
        catch
        {
            return 81;
        }
    }
}
