using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Untrusted project-integrity evidence.
///
/// Construction or possession of this object proves nothing and grants
/// no authority.
///
/// Evidence must be independently validated against an immutable,
/// independently trusted ProjectIntegrityPolicy.
///
/// Raw signing keys, private keys, recovery secrets, VeraCrypt secrets,
/// user secrets, and plaintext protected source material must never be
/// placed in this object.
/// </summary>
public sealed class ProjectIntegrityEvidence
{
    private readonly byte[] _projectManifestDigest;
    private readonly byte[] _sourceTreeDigest;
    private readonly byte[] _approvedWorkloadDigest;
    private readonly byte[] _challengeBinding;

    public ProjectIntegrityEvidence(
        string projectIdentity,
        string manifestIdentity,
        byte[] projectManifestDigest,
        byte[] sourceTreeDigest,
        byte[] approvedWorkloadDigest,
        byte[] challengeBinding,
        DateTimeOffset observedAt)
    {
        ProjectIdentity = RequireText(
            projectIdentity,
            nameof(projectIdentity));

        ManifestIdentity = RequireText(
            manifestIdentity,
            nameof(manifestIdentity));

        _projectManifestDigest = CopyRequired(
            projectManifestDigest,
            nameof(projectManifestDigest));

        _sourceTreeDigest = CopyRequired(
            sourceTreeDigest,
            nameof(sourceTreeDigest));

        _approvedWorkloadDigest = CopyRequired(
            approvedWorkloadDigest,
            nameof(approvedWorkloadDigest));

        _challengeBinding = CopyRequired(
            challengeBinding,
            nameof(challengeBinding));

        ObservedAt = observedAt;
    }

    public string ProjectIdentity { get; }

    public string ManifestIdentity { get; }

    public byte[] ProjectManifestDigest =>
        (byte[])_projectManifestDigest.Clone();

    public byte[] SourceTreeDigest =>
        (byte[])_sourceTreeDigest.Clone();

    public byte[] ApprovedWorkloadDigest =>
        (byte[])_approvedWorkloadDigest.Clone();

    public byte[] ChallengeBinding =>
        (byte[])_challengeBinding.Clone();

    public DateTimeOffset ObservedAt { get; }

    private static string RequireText(
        string value,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "Value must not be empty.",
                parameterName);
        }

        return value;
    }

    private static byte[] CopyRequired(
        byte[] value,
        string parameterName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (value.Length == 0)
        {
            throw new ArgumentException(
                "Digest or binding must not be empty.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}