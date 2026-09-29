using System;
using System.Collections.Generic;
using System.Text.Json;
using IMortal.TrustBroker.Security.ConfidentialCompute;

internal static class Harness
{
    static readonly UserDeviceProofOfPossessionChallengeCanonicalSerializer Serializer = new();
    static readonly UserDeviceProofOfPossessionChallengeData Base = new(
        "1", "audit-protocol", "audit-challenge", "audit-nonce", "audit-account",
        new string('a', 64), "audit-purpose", 1700000000, 1700000300);
    static readonly Dictionary<string, string> Vectors = new();
    static readonly List<string> Passed = new();

    static void Vector(string name, UserDeviceProofOfPossessionChallengeData value)
    {
        byte[] first = Serializer.Serialize(value);
        byte[] second = Serializer.Serialize(value);
        if (!first.AsSpan().SequenceEqual(second)) throw new Exception("Nondeterministic output: " + name);
        Vectors.Add(name, Convert.ToBase64String(first));
    }

    static void Reject<T>(string name, Action action) where T : Exception
    {
        try { action(); }
        catch (T) { Passed.Add(name); return; }
        throw new Exception("Required rejection absent: " + name);
    }

    public static int Main()
    {
        try
        {
            Vector("normal", Base);
            Vector("zero", Base with { IssuedAtUnixTimeSeconds = 0, ExpiresAtUnixTimeSeconds = 0 });
            Vector("negative", Base with { IssuedAtUnixTimeSeconds = -2, ExpiresAtUnixTimeSeconds = -1 });
            Vector("maximum_convertible", Base with { IssuedAtUnixTimeSeconds = long.MaxValue / 1000, ExpiresAtUnixTimeSeconds = long.MaxValue / 1000 });
            Vector("minimum_convertible", Base with { IssuedAtUnixTimeSeconds = long.MinValue / 1000, ExpiresAtUnixTimeSeconds = long.MinValue / 1000 });
            Vector("nfc", Base with { AccountIdentity = "caf\u00e9" });
            Vector("multibyte", Base with { AccountIdentity = "\u8d26\u6237\U0001f512" });
            Vector("maximum_string", Base with { AccountIdentity = new string('x', 16384) });
            Vector("maximum_multibyte_string", Base with { AccountIdentity = new string('\u00e9', 8192) });
            Reject<OverflowException>("issued_positive_overflow", () => Serializer.Serialize(Base with { IssuedAtUnixTimeSeconds = long.MaxValue / 1000 + 1 }));
            Reject<OverflowException>("issued_negative_overflow", () => Serializer.Serialize(Base with { IssuedAtUnixTimeSeconds = long.MinValue / 1000 - 1 }));
            Reject<OverflowException>("expiry_positive_overflow", () => Serializer.Serialize(Base with { ExpiresAtUnixTimeSeconds = long.MaxValue / 1000 + 1 }));
            Reject<OverflowException>("expiry_negative_overflow", () => Serializer.Serialize(Base with { ExpiresAtUnixTimeSeconds = long.MinValue / 1000 - 1 }));
            Reject<ArgumentNullException>("null_challenge", () => Serializer.Serialize(null!));
            Reject<ArgumentNullException>("null_field", () => Serializer.Serialize(Base with { AccountIdentity = null! }));
            Reject<ArgumentException>("empty_field", () => Serializer.Serialize(Base with { AccountIdentity = "" }));
            Reject<ArgumentException>("decomposed_unicode", () => Serializer.Serialize(Base with { AccountIdentity = "e\u0301" }));
            Reject<ArgumentException>("invalid_unicode", () => Serializer.Serialize(Base with { AccountIdentity = "\ud800" }));
            Reject<ArgumentOutOfRangeException>("oversized_ascii", () => Serializer.Serialize(Base with { AccountIdentity = new string('x', 16385) }));
            Reject<ArgumentOutOfRangeException>("oversized_utf8", () => Serializer.Serialize(Base with { AccountIdentity = new string('\u00e9', 8193) }));
            Console.WriteLine(JsonSerializer.Serialize(new { Vectors, Rejections = Passed }));
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error.ToString()); return 1; }
    }
}
