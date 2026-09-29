using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable expected project-integrity policy material.
///
/// This contract describes expected identities and digests only.
///
/// Construction or possession of this object grants no source-mutation,
/// production, signing, workload, trading, provider-dispatch, user-runtime,
/// or I-Mortal Security Umbrella root authority.
/// </summary>
public sealed class ProjectIntegrityPolicy
{
    private readonly byte[] _requiredProjectManifestDigest;
    private readonly byte[] _requiredSourceTreeDigest;
    private readonly byte[] _requiredApprovedWorkloadDigest;

    public ProjectIntegrityPolicy(
        string projectIdentity,
        string manifestIdentity,
        byte[] requiredProjectManifestDigest,
        byte[] requiredSourceTreeDigest,
        byte[] requiredApprovedWorkloadDigest)
    {
        ProjectIdentity = RequireText(
            projectIdentity,
            nameof(projectIdentity));

        ManifestIdentity = RequireText(
            manifestIdentity,
            nameof(manifestIdentity));

        _requiredProjectManifestDigest = CopyRequired(
            requiredProjectManifestDigest,
            nameof(requiredProjectManifestDigest));

        _requiredSourceTreeDigest = CopyRequired(
            requiredSourceTreeDigest,
            nameof(requiredSourceTreeDigest));

        _requiredApprovedWorkloadDigest = CopyRequired(
            requiredApprovedWorkloadDigest,
            nameof(requiredApprovedWorkloadDigest));
    }

    public string ProjectIdentity { get; }

    public string ManifestIdentity { get; }

    public byte[] RequiredProjectManifestDigest =>
        (byte[])_requiredProjectManifestDigest.Clone();

    public byte[] RequiredSourceTreeDigest =>
        (byte[])_requiredSourceTreeDigest.Clone();

    public byte[] RequiredApprovedWorkloadDigest =>
        (byte[])_requiredApprovedWorkloadDigest.Clone();

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
                "Required digest must not be empty.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}