using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class ProtectedOperationStructuralNonReachabilityTests
{
    private const string SourceRoot =
        @"PUBLIC_DEPLOYMENT_PATH_REMOVED";

    private const string TestRoot =
        @"PUBLIC_DEPLOYMENT_PATH_REMOVED";

    private const string ContractPath =
        @"PUBLIC_DEPLOYMENT_PATH_REMOVED";

    private const string ContractSha256 =
        "PUBLIC_DIGEST_REMOVED";

    private static readonly string[] ProtectedOperationNames =
    [
        "EnrollAsync",
        "AuthorizeAsync",
        "AttestAsync",
        "SignAsync",
        "RevokeAsync"
    ];

    [TestMethod]
    public void FrozenContract_HashAndFailClosedSemanticsRemainExact()
    {
        Assert.IsTrue(File.Exists(ContractPath));

        byte[] bytes = File.ReadAllBytes(ContractPath);
        string hash = Convert.ToHexString(SHA256.HashData(bytes))
            .ToLowerInvariant();

        Assert.AreEqual(ContractSha256, hash);

        string text = File.ReadAllText(ContractPath);

        string[] required =
        [
            "status=FROZEN",
            "fail_closed=true",
            "structural_non_reachability_observed=true",
            "protected_provider_callers_outside_provider_definitions=0",
            "mutating_hardware_api_matches=0",
            "database_api_matches=0",
            "trust_operation_boundary_dispatch_callers=0",
            "startup_decision_protected_path_references=0",
            "provider_operation_implementations_are_disabled_stubs=true",
            "automatic_provider_dispatch_allowed=false",
            "automatic_hardware_mutation_allowed=false",
            "automatic_database_open_allowed=false",
            "production_authorized=false",
            "provider_dispatch_enabled=false",
            "live_trading_enabled=false"
        ];

        foreach (string requiredLine in required)
        {
            Assert.AreEqual(
                1,
                text.Split('\n')
                    .Count(line => line == requiredLine),
                requiredLine);
        }
    }

    [TestMethod]
    public void ProductionCallGraph_HasNoProtectedProviderCallers()
    {
        Regex protectedCall = new(
            @"\.(EnrollAsync|AuthorizeAsync|AttestAsync|SignAsync|RevokeAsync)\s*\(",
            RegexOptions.CultureInvariant);

        string[] callers =
            ProductionFiles()
                .Where(path => !IsProviderSource(path))
                .Where(path => protectedCall.IsMatch(File.ReadAllText(path)))
                .ToArray();

        CollectionAssert.AreEqual(
            Array.Empty<string>(),
            callers);
    }

    [TestMethod]
    public void ProductionSource_HasNoMutatingHardwareApis()
    {
        Regex mutation = new(
            @"NCryptCreatePersistedKey|NCryptFinalizeKey|NCryptDeleteKey|" +
            @"NCryptSetProperty|SecKeyCreateRandomKey|CreatePersistedKey|DeleteKey",
            RegexOptions.CultureInvariant);

        string[] matches =
            ProductionFiles()
                .Where(path => mutation.IsMatch(File.ReadAllText(path)))
                .ToArray();

        CollectionAssert.AreEqual(
            Array.Empty<string>(),
            matches);
    }

    [TestMethod]
    public void ProductionSource_HasNoDatabaseApis()
    {
        Regex database = new(
            @"SqliteConnection|SQLiteConnection|SqlCipher|SQLCipher|" +
            @"authentication\.db|replay.*\.db",
            RegexOptions.CultureInvariant);

        string[] matches =
            ProductionFiles()
                .Where(path => database.IsMatch(File.ReadAllText(path)))
                .ToArray();

        CollectionAssert.AreEqual(
            Array.Empty<string>(),
            matches);
    }

    [TestMethod]
    public void TrustOperationBoundary_HasNoProductionDispatchCaller()
    {
        const string call =
            "TrustOperationBoundary.ValidateForDispatch(";

        string boundaryPath =
            Path.Combine(
                SourceRoot,
                "Providers",
                "TrustOperationBoundary.cs");

        string[] callers =
            ProductionFiles()
                .Where(path =>
                    !path.Equals(
                        boundaryPath,
                        StringComparison.OrdinalIgnoreCase))
                .Where(path =>
                    File.ReadAllText(path).Contains(
                        call,
                        StringComparison.Ordinal))
                .ToArray();

        CollectionAssert.AreEqual(
            Array.Empty<string>(),
            callers);
    }

    [TestMethod]
    public void StartupDecision_HasNoProtectedPathReference()
    {
        string path =
            Path.Combine(
                SourceRoot,
                "Security",
                "ProductionStartupDecision.cs");

        string text = File.ReadAllText(path);

        string[] forbidden =
        [
            "TrustProviderFactory",
            ".Detect(",
            ".EnrollAsync(",
            ".AuthorizeAsync(",
            ".AttestAsync(",
            ".SignAsync(",
            ".RevokeAsync(",
            "TrustOperationBoundary"
        ];

        foreach (string value in forbidden)
        {
            Assert.IsFalse(
                text.Contains(value, StringComparison.Ordinal),
                value);
        }
    }

    [TestMethod]
    public void ConcreteProviders_RemainFailClosedForAllProtectedOperations()
    {
        AssertProviderDisabled(
            Path.Combine(
                SourceRoot,
                "Providers",
                "Windows",
                "WindowsTpmProvider.cs"),
            "TPM_OPERATION_DISABLED");

        AssertProviderDisabled(
            Path.Combine(
                SourceRoot,
                "Providers",
                "Linux",
                "LinuxTpmProvider.cs"),
            "TPM_OPERATION_DISABLED");

        AssertProviderDisabled(
            Path.Combine(
                SourceRoot,
                "Providers",
                "MacOS",
                "MacOsSecureEnclaveProvider.cs"),
            "SECURE_ENCLAVE_OPERATION_DISABLED");

        AssertProviderDisabled(
            Path.Combine(
                SourceRoot,
                "Providers",
                "IOS",
                "IosSecureEnclaveProvider.cs"),
            "IOS_SECURE_ENCLAVE_OPERATION_DISABLED");

        AssertProviderDisabled(
            Path.Combine(
                SourceRoot,
                "Providers",
                "Android",
                "AndroidKeystoreProvider.cs"),
            "ANDROID_KEYSTORE_OPERATION_DISABLED");
    }

    private static void AssertProviderDisabled(
        string path,
        string disabledCode)
    {
        Assert.IsTrue(File.Exists(path), path);

        string text = File.ReadAllText(path);

        int disabledCount =
            Regex.Matches(
                text,
                Regex.Escape(disabledCode),
                RegexOptions.CultureInvariant)
            .Count;

        Assert.AreEqual(
            ProtectedOperationNames.Length,
            disabledCount,
            path);
    }

    private static string[] ProductionFiles()
    {
        return Directory
            .EnumerateFiles(
                SourceRoot,
                "*.cs",
                SearchOption.AllDirectories)
            .Where(path =>
                !path.StartsWith(
                    TestRoot + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
            .Where(path =>
                !path.Contains(
                    $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
                    StringComparison.OrdinalIgnoreCase))
            .Where(path =>
                !path.Contains(
                    $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                    StringComparison.OrdinalIgnoreCase))
            .OrderBy(
                path => path,
                StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool IsProviderSource(string path)
    {
        string providerRoot =
            Path.Combine(SourceRoot, "Providers") +
            Path.DirectorySeparatorChar;

        return path.StartsWith(
            providerRoot,
            StringComparison.OrdinalIgnoreCase);
    }
}
