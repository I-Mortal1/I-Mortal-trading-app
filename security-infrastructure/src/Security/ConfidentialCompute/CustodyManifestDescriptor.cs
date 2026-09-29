using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Describes a custody manifest without asserting that the manifest is
/// authentic, trusted, accepted, or authorized.
/// </summary>
public sealed class CustodyManifestDescriptor
{
    private readonly byte[] _manifestDigest;

    public CustodyManifestDescriptor(
        string manifestVersion,
        string custodyDomain,
        byte[] manifestDigest)
    {
        if (string.IsNullOrWhiteSpace(manifestVersion))
        {
            throw new ArgumentException(
                "Manifest version is required.",
                nameof(manifestVersion));
        }

        if (string.IsNullOrWhiteSpace(custodyDomain))
        {
            throw new ArgumentException(
                "Custody domain is required.",
                nameof(custodyDomain));
        }

        ArgumentNullException.ThrowIfNull(manifestDigest);

        if (manifestDigest.Length == 0)
        {
            throw new ArgumentException(
                "Manifest digest must not be empty.",
                nameof(manifestDigest));
        }

        ManifestVersion = manifestVersion;
        CustodyDomain = custodyDomain;
        _manifestDigest = (byte[])manifestDigest.Clone();
    }

    public string ManifestVersion { get; }

    public string CustodyDomain { get; }

    public byte[] ManifestDigest => (byte[])_manifestDigest.Clone();
}