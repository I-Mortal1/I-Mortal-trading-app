using System;
using System.Collections.Generic;
using System.Globalization;
using IMortal.TrustBroker.Security.ConfidentialCompute;

internal static class Harness
{
    private const string Signature = "ECDSA-P256-SHA256-P1363";
    private const string PublicKey = "EC-P256";
    private static int checks;
    private static int accepted;
    private static int rejected;

    private static void Check(string? signature, string? key)
    {
        // Independent oracle: the exact pair in the frozen policy.
        bool expected = string.Equals(signature, Signature, StringComparison.Ordinal)
            && string.Equals(key, PublicKey, StringComparison.Ordinal);
        var concrete = new UserDeviceProofOfPossessionSignatureAlgorithmAllowlist();
        IUserDeviceProofOfPossessionSignatureAlgorithmAllowlist boundary = concrete;
        bool direct = concrete.IsAllowed(signature!, key!);
        bool throughInterface = boundary.IsAllowed(signature!, key!);
        if (direct != expected || throughInterface != expected)
            throw new InvalidOperationException($"Allowlist mismatch at case {checks + 1}.");
        checks++;
        if (expected) accepted++; else rejected++;
    }

    private static IEnumerable<string?> Variants(string value)
    {
        yield return null;
        yield return "";
        yield return " ";
        yield return value;
        yield return value.ToLowerInvariant();
        yield return " " + value;
        yield return value + " ";
        yield return "\t" + value;
        yield return value + "\r\n";
        yield return value + "\0";
        yield return "\0" + value;
        yield return value + "\u200b";
        yield return value + "\u00a0";
        yield return value + "\ud800";
        yield return value.Replace('-', '\u2011');
        yield return value.Replace('E', '\uff25');
        yield return value.Replace('-', '_');
        yield return value + ",OTHER";
        yield return value + ";OTHER";
        yield return value + "/OTHER";
        yield return new string('X', 65536);
    }

    private static void Mutations(string original, bool signatureSide)
    {
        void Test(string value)
        {
            if (signatureSide) Check(value, PublicKey);
            else Check(Signature, value);
        }
        for (int index = 0; index < original.Length; index++)
        {
            Test(original.Remove(index, 1));
            for (int character = 0; character < 128; character++)
            {
                if (character == original[index]) continue;
                char[] mutated = original.ToCharArray();
                mutated[index] = (char)character;
                Test(new string(mutated));
            }
        }
        for (int index = 0; index <= original.Length; index++)
            foreach (char character in new[] { '\0', ' ', '\t', '-', '\u200b', '\u00a0' })
                Test(original.Insert(index, character.ToString()));
    }

    public static int Main()
    {
        try
        {
            if (UserDeviceProofOfPossessionSignatureAlgorithmAllowlist.ApprovedSignatureAlgorithm != Signature
                || UserDeviceProofOfPossessionSignatureAlgorithmAllowlist.ApprovedPublicKeyAlgorithm != PublicKey)
                throw new InvalidOperationException("Implementation constants disagree with frozen policy.");

            foreach (string cultureName in new[] { "", "en-US", "tr-TR", "az-Latn-AZ" })
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
                CultureInfo.CurrentUICulture = CultureInfo.CurrentCulture;
                foreach (string? signature in Variants(Signature))
                    foreach (string? key in Variants(PublicKey))
                        Check(signature, key);

                foreach (string alias in new[] {
                    "ES256", "ECDSA", "ECDSA-P256-SHA256", "ECDSA-P256-SHA256-DER",
                    "ECDSA-P384-SHA384-P1363", "ECDSA-P256-SHA1-P1363", "Ed25519",
                    "RSA-PSS-SHA256", "RS256", "none", PublicKey })
                    Check(alias, PublicKey);
                foreach (string alias in new[] {
                    "P-256", "secp256r1", "prime256v1", "EC", "EC-P384", "RSA",
                    "Ed25519", "none", Signature })
                    Check(Signature, alias);

                Mutations(Signature, signatureSide: true);
                Mutations(PublicKey, signatureSide: false);
                // Repeated calls across alternating accepted/rejected inputs.
                var shared = new UserDeviceProofOfPossessionSignatureAlgorithmAllowlist();
                for (int i = 0; i < 100; i++)
                {
                    if (!shared.IsAllowed(Signature, PublicKey)
                        || shared.IsAllowed("ES256", PublicKey)
                        || shared.IsAllowed(Signature, "P-256")
                        || !shared.IsAllowed(Signature, PublicKey))
                        throw new InvalidOperationException("Repeated-call behavior changed.");
                }
                Console.WriteLine("CULTURE_PASS=" + (cultureName.Length == 0 ? "INVARIANT" : cultureName));
            }
            Console.WriteLine("INPUT_PAIRS_CHECKED=" + checks);
            Console.WriteLine("ACCEPTED_PAIRS=" + accepted);
            Console.WriteLine("REJECTED_PAIRS=" + rejected);
            Console.WriteLine("DIRECT_AND_INTERFACE_CHECKS=" + checks * 2);
            Console.WriteLine("REPEATED_CALL_CHECKS=1600");
            Console.WriteLine("ALLOWLIST_BEHAVIOR=PASS");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("ALLOWLIST_BEHAVIOR=FAIL: " + error.Message);
            return 1;
        }
    }
}
