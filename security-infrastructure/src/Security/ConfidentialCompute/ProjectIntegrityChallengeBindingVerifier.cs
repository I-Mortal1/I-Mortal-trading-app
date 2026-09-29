using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Exact fail-closed Project Integrity challenge-binding verifier.
///
/// The expected ChallengeBinding is independently reconstructed from the
/// authoritative AttestationChallenge and the integrity evidence.
///
/// This is a domain-separated SHA-256 transcript binding.
///
/// This verifier does not grant source-mutation, production, signing,
/// workload-execution, user-runtime, developer-source, or umbrella-root
/// authority.
/// </summary>
public sealed class ProjectIntegrityChallengeBindingVerifier :
    IProjectIntegrityChallengeBindingVerifier
{
    private const string BindingDomain =
        "I-MORTAL/PROJECT-INTEGRITY/CHALLENGE-BINDING/V1";

    public bool Verify(
        ProjectIntegrityEvidence evidence,
        AttestationChallenge challenge,
        DateTimeOffset now)
    {
        try
        {
            if (evidence is null ||
                challenge is null)
            {
                return false;
            }

            if (now == default)
            {
                return false;
            }

            if (!ValidateChallenge(
                    challenge,
                    now))
            {
                return false;
            }

            if (!ValidateEvidence(
                    evidence,
                    challenge,
                    now))
            {
                return false;
            }

            byte[] suppliedBinding =
                evidence.ChallengeBinding;

            if (suppliedBinding is null ||
                suppliedBinding.Length != SHA256.HashSizeInBytes)
            {
                return false;
            }

            byte[] expectedBinding =
                ComputeExpectedBinding(
                    evidence,
                    challenge);

            if (expectedBinding.Length !=
                SHA256.HashSizeInBytes)
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(
                suppliedBinding,
                expectedBinding);
        }
        catch
        {
            // Security boundary: every unexpected condition denies.
            return false;
        }
    }

    private static bool ValidateChallenge(
        AttestationChallenge challenge,
        DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(
                challenge.ChallengeId))
        {
            return false;
        }

        byte[] nonce = challenge.Nonce;

        if (nonce is null ||
            nonce.Length < 16)
        {
            return false;
        }

        if (challenge.IssuedAt == default ||
            challenge.ExpiresAt == default)
        {
            return false;
        }

        if (challenge.ExpiresAt <=
            challenge.IssuedAt)
        {
            return false;
        }

        if (challenge.IssuedAt > now)
        {
            return false;
        }

        if (challenge.ExpiresAt <= now)
        {
            return false;
        }

        if (challenge.ExpectedPlatform is not
            (ConfidentialPlatformClass.IntelTdx or
             ConfidentialPlatformClass.AmdSevSnp))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(
                challenge.WorkloadBinding))
        {
            return false;
        }

        return true;
    }

    private static bool ValidateEvidence(
        ProjectIntegrityEvidence evidence,
        AttestationChallenge challenge,
        DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(
                evidence.ProjectIdentity))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(
                evidence.ManifestIdentity))
        {
            return false;
        }

        if (!RequiredDigest(
                evidence.ProjectManifestDigest))
        {
            return false;
        }

        if (!RequiredDigest(
                evidence.SourceTreeDigest))
        {
            return false;
        }

        if (!RequiredDigest(
                evidence.ApprovedWorkloadDigest))
        {
            return false;
        }

        if (evidence.ObservedAt == default)
        {
            return false;
        }

        // Integrity evidence must belong temporally to the exact challenge.
        if (evidence.ObservedAt <
            challenge.IssuedAt)
        {
            return false;
        }

        if (evidence.ObservedAt >=
            challenge.ExpiresAt)
        {
            return false;
        }

        if (evidence.ObservedAt > now)
        {
            return false;
        }

        return true;
    }

    private static bool RequiredDigest(
        byte[] value)
    {
        return value is not null &&
               value.Length == SHA256.HashSizeInBytes;
    }

    private static byte[] ComputeExpectedBinding(
        ProjectIntegrityEvidence evidence,
        AttestationChallenge challenge)
    {
        using MemoryStream stream =
            new MemoryStream();

        WriteString(
            stream,
            BindingDomain);

        WriteString(
            stream,
            challenge.ChallengeId);

        WriteBytes(
            stream,
            challenge.Nonce);

        WriteInt64(
            stream,
            challenge.IssuedAt.UtcTicks);

        WriteInt64(
            stream,
            challenge.ExpiresAt.UtcTicks);

        WriteInt32(
            stream,
            (int)challenge.ExpectedPlatform);

        WriteString(
            stream,
            challenge.WorkloadBinding);

        WriteString(
            stream,
            evidence.ProjectIdentity);

        WriteString(
            stream,
            evidence.ManifestIdentity);

        WriteBytes(
            stream,
            evidence.ProjectManifestDigest);

        WriteBytes(
            stream,
            evidence.SourceTreeDigest);

        WriteBytes(
            stream,
            evidence.ApprovedWorkloadDigest);

        WriteInt64(
            stream,
            evidence.ObservedAt.UtcTicks);

        return SHA256.HashData(
            stream.GetBuffer().AsSpan(
                0,
                checked((int)stream.Length)));
    }

    private static void WriteString(
        Stream stream,
        string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException(
                "Canonical string must not be empty.");
        }

        byte[] bytes =
            Encoding.UTF8.GetBytes(value);

        WriteBytes(
            stream,
            bytes);
    }

    private static void WriteBytes(
        Stream stream,
        byte[] value)
    {
        if (value is null ||
            value.Length == 0)
        {
            throw new InvalidDataException(
                "Canonical binary field must not be empty.");
        }

        WriteInt32(
            stream,
            value.Length);

        stream.Write(
            value,
            0,
            value.Length);
    }

    private static void WriteInt32(
        Stream stream,
        int value)
    {
        Span<byte> buffer =
            stackalloc byte[sizeof(int)];

        BinaryPrimitives.WriteInt32BigEndian(
            buffer,
            value);

        stream.Write(buffer);
    }

    private static void WriteInt64(
        Stream stream,
        long value)
    {
        Span<byte> buffer =
            stackalloc byte[sizeof(long)];

        BinaryPrimitives.WriteInt64BigEndian(
            buffer,
            value);

        stream.Write(buffer);
    }
}