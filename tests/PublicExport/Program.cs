using System.Security.Cryptography;
using IMortal.TrustBroker.Security;
using IMortal.TrustBroker.Providers;
using IMortal.TrustBroker.Providers.Windows;
using IMortal.TrustBroker.Providers.Linux;
using IMortal.TrustBroker.Providers.MacOS;
using IMortal.TrustBroker.Providers.Android;
using IMortal.TrustBroker.Providers.IOS;

int checks = 0;
void Require(bool condition, string name)
{
    if (!condition) throw new InvalidOperationException(name);
    checks++;
}
void Denied(ProductionRuntimeGateResult result, string name)
{
    Require(!result.ContractVerified && !result.ProductionAuthorized &&
        !result.ProviderDispatchAllowed, name);
}

var temporary = Path.Combine(Path.GetTempPath(), "imortal-public-test-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temporary);
try
{
    var path = Path.Combine(temporary, "synthetic.conf");
    Denied(ProductionRuntimeGate.Verify(path, "PUBLIC_DIGEST_REMOVED"), "Missing anchor denied");
    File.WriteAllText(path, "production_authorized=true\n");
    Denied(ProductionRuntimeGate.Verify(path, "PUBLIC_DIGEST_REMOVED"), "Removed anchor denied");
    Denied(ProductionRuntimeGate.Verify(path, new string('0', 64)), "Wrong anchor denied");
    // Test-only trusted value for this freshly created fixture, never a runtime
    // mechanism for learning authoritative trust anchors from candidate policies.
    var fixtureDigest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
    Denied(ProductionRuntimeGate.Verify(path, fixtureDigest), "Unauthorized policy denied despite matching bytes");
    var template = Path.Combine("security-infrastructure", "specification-templates", "security-spec",
        "I_MORTAL_CROSS_PLATFORM_VALIDATION_GATE_V1.conf.example");
    File.Copy(template, path, overwrite: true);
    fixtureDigest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
    var verified = ProductionRuntimeGate.Verify(path, fixtureDigest);
    Require(verified.ContractVerified && !verified.ProductionAuthorized && !verified.ProviderDispatchAllowed,
        "Verification does not authorize production");
    File.AppendAllText(path, "production_authorized=true\n");
    fixtureDigest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
    Denied(ProductionRuntimeGate.Verify(path, fixtureDigest), "Duplicate authorization denied");

    ITrustProvider[] providers = [new WindowsTpmProvider(), new LinuxTpmProvider(),
        new MacOsSecureEnclaveProvider(), new AndroidKeystoreProvider(), new IosSecureEnclaveProvider()];
    var request = new AuthorizationRequest("public-test", "test-only", "synthetic-device",
        "synthetic-nonce", DateTimeOffset.UtcNow.AddMinutes(1), "test-only", "test-only");
    foreach (var provider in providers)
    {
        // Do not invoke Detect or IsAvailable: these checks require no hardware.
        var enrolled = await provider.EnrollAsync(request, CancellationToken.None);
        Require(!enrolled.Success, provider.ProviderId + " enrollment denied");
        var results = new[] {
            await provider.AuthorizeAsync(request, CancellationToken.None),
            await provider.AttestAsync(request, CancellationToken.None),
            await provider.SignAsync(request, new byte[] { 1 }, CancellationToken.None),
            await provider.RevokeAsync(request, CancellationToken.None)
        };
        foreach (var result in results) Require(!result.Success, provider.ProviderId + " operation denied");
    }
}
finally { Directory.Delete(temporary, recursive: true); }
Console.WriteLine($"PUBLIC_EXPORT_BEHAVIOR=PASS; CHECKS={checks}");
