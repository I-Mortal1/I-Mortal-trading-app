using Microsoft.VisualStudio.TestTools.UnitTesting;
using IMortal.TrustBroker.Security;

namespace IMortal.TrustBroker.Conformance;

[TestClass]
public sealed class ProductionStartupDecisionConformanceTests
{
    private const string AuthoritativeF23ZSha256 =
        "PUBLIC_DIGEST_REMOVED";

    private sealed class CountingSideEffectObserver :
        IProductionStartupSideEffectObserver
    {
        public int ProviderOperationCount { get; private set; }
        public int HardwareMutationCount { get; private set; }
        public int DatabaseOpenCount { get; private set; }
        public int KekCreationCount { get; private set; }
        public int DekGenerationCount { get; private set; }

        public void ProviderOperation()
        {
            ProviderOperationCount++;
        }

        public void HardwareMutation()
        {
            HardwareMutationCount++;
        }

        public void DatabaseOpen()
        {
            DatabaseOpenCount++;
        }

        public void KekCreation()
        {
            KekCreationCount++;
        }

        public void DekGeneration()
        {
            DekGenerationCount++;
        }
    }

    [TestMethod]
    public void MissingContract_IsDeniedWithZeroSideEffects()
    {
        var observer = new CountingSideEffectObserver();

        var path = Path.Combine(
            Path.GetTempPath(),
            Guid.NewGuid().ToString("N"),
            "missing-f23z.conf");

        var result =
            ProductionStartupDecision.Evaluate(
                path,
                AuthoritativeF23ZSha256,
                observer);

        AssertDeniedAndZeroSideEffects(result, observer);
    }

    [TestMethod]
    public void WrongHash_IsDeniedWithZeroSideEffects()
    {
        using var temp = SyntheticContract.CopyAuthoritative();

        var observer = new CountingSideEffectObserver();

        var result =
            ProductionStartupDecision.Evaluate(
                temp.Path,
                new string('0', 64),
                observer);

        AssertDeniedAndZeroSideEffects(result, observer);
    }

    [TestMethod]
    public void MalformedContract_IsDeniedWithZeroSideEffects()
    {
        using var temp =
            SyntheticContract.FromText(
                "this-is-not-a-key-value-line\n");

        var observer = new CountingSideEffectObserver();

        var result =
            ProductionStartupDecision.EvaluateCandidateForTests(
                temp.Path,
                observer);

        AssertDeniedAndZeroSideEffects(result, observer);
    }

    [TestMethod]
    public void DuplicateKey_IsDeniedWithZeroSideEffects()
    {
        using var temp =
            SyntheticContract.FromText(
                "fail_closed=true\n" +
                "fail_closed=true\n");

        var observer = new CountingSideEffectObserver();

        var result =
            ProductionStartupDecision.EvaluateCandidateForTests(
                temp.Path,
                observer);

        AssertDeniedAndZeroSideEffects(result, observer);
    }

    [TestMethod]
    public void MissingRequiredSemantic_IsDeniedWithZeroSideEffects()
    {
        using var temp =
            SyntheticContract.FromAuthoritativeMutation(
                lines => lines
                    .Where(line =>
                        !line.Equals(
                            "fail_closed=true",
                            StringComparison.Ordinal))
                    .ToArray());

        var observer = new CountingSideEffectObserver();

        var result =
            ProductionStartupDecision.EvaluateCandidateForTests(
                temp.Path,
                observer);

        AssertDeniedAndZeroSideEffects(result, observer);
    }

    [TestMethod]
    public void UnknownSemantic_IsDeniedWithZeroSideEffects()
    {
        using var temp =
            SyntheticContract.FromAuthoritativeMutation(
                lines =>
                    lines
                        .Concat(
                            new[]
                            {
                                "unknown_security_semantic=true"
                            })
                        .ToArray());

        var observer = new CountingSideEffectObserver();

        var result =
            ProductionStartupDecision.EvaluateCandidateForTests(
                temp.Path,
                observer);

        AssertDeniedAndZeroSideEffects(result, observer);
    }

    [TestMethod]
    public void AlteredSecuritySemantic_IsDeniedWithZeroSideEffects()
    {
        using var temp =
            SyntheticContract.FromAuthoritativeMutation(
                lines =>
                    lines
                        .Select(line =>
                            line.Equals(
                                "fail_closed=true",
                                StringComparison.Ordinal)
                                ? "fail_closed=false"
                                : line)
                        .ToArray());

        var observer = new CountingSideEffectObserver();

        var result =
            ProductionStartupDecision.EvaluateCandidateForTests(
                temp.Path,
                observer);

        AssertDeniedAndZeroSideEffects(result, observer);
    }

    [TestMethod]
    public void ValidAuthoritativeContract_VerifiesButRemainsDenied()
    {
        var observer = new CountingSideEffectObserver();

        const string path =
            @"PUBLIC_DEPLOYMENT_PATH_REMOVED";

        var result =
            ProductionStartupDecision.Evaluate(
                path,
                AuthoritativeF23ZSha256,
                observer);

        Assert.IsTrue(result.ContractVerified);
        Assert.IsFalse(result.ProductionAuthorized);
        Assert.IsFalse(result.ProviderDispatchAllowed);

        AssertZeroSideEffects(observer);
    }

    private static void AssertDeniedAndZeroSideEffects(
        ProductionStartupDecisionResult result,
        CountingSideEffectObserver observer)
    {
        Assert.IsFalse(result.ProductionAuthorized);
        Assert.IsFalse(result.ProviderDispatchAllowed);

        AssertZeroSideEffects(observer);
    }

    private static void AssertZeroSideEffects(
        CountingSideEffectObserver observer)
    {
        Assert.AreEqual(0, observer.ProviderOperationCount);
        Assert.AreEqual(0, observer.HardwareMutationCount);
        Assert.AreEqual(0, observer.DatabaseOpenCount);
        Assert.AreEqual(0, observer.KekCreationCount);
        Assert.AreEqual(0, observer.DekGenerationCount);
    }

    private sealed class SyntheticContract : IDisposable
    {
        private const string AuthoritativePath =
            @"PUBLIC_DEPLOYMENT_PATH_REMOVED";

        private SyntheticContract(string directory, string path)
        {
            Directory = directory;
            Path = path;
        }

        private string Directory { get; }

        public string Path { get; }

        public static SyntheticContract CopyAuthoritative()
        {
            var lines =
                File.ReadAllLines(AuthoritativePath);

            return FromLines(lines);
        }

        public static SyntheticContract FromAuthoritativeMutation(
            Func<string[], string[]> mutation)
        {
            var lines =
                File.ReadAllLines(AuthoritativePath);

            return FromLines(mutation(lines));
        }

        public static SyntheticContract FromText(string text)
        {
            var directory =
                System.IO.Path.Combine(
                    System.IO.Path.GetTempPath(),
                    "i-mortal-f24p-" + Guid.NewGuid().ToString("N"));

            System.IO.Directory.CreateDirectory(directory);

            var path =
                System.IO.Path.Combine(
                    directory,
                    "synthetic-f23z.conf");

            File.WriteAllText(
                path,
                text.Replace("\r\n", "\n").Replace("\r", "\n"),
                new System.Text.UTF8Encoding(false));

            return new SyntheticContract(directory, path);
        }

        private static SyntheticContract FromLines(
            IEnumerable<string> lines)
        {
            var text =
                string.Join("\n", lines) + "\n";

            return FromText(text);
        }

        public void Dispose()
        {
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, true);
        }
    }
}
