using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Untrusted provenance material supplied for independent verification.
/// This object does not assert that its signature or identity is valid.
/// </summary>
public sealed class CustodyManifestProvenance
{
    private readonly byte[] _manifestDigest;
    private readonly byte[] _signature;

    public CustodyManifestProvenance(
        string manifestVersion,
        string custodyDomain,
        byte[] manifestDigest,
        string securityBoundaryIdentity,
        string verifierMeasurement,
        ConfidentialPlatformClass platformClass,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        byte[] signature)
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

        if (string.IsNullOrWhiteSpace(securityBoundaryIdentity))
        {
            throw new ArgumentException(
                "Security-boundary identity is required.",
                nameof(securityBoundaryIdentity));
        }

        if (string.IsNullOrWhiteSpace(verifierMeasurement))
        {
            throw new ArgumentException(
                "Verifier measurement is required.",
                nameof(verifierMeasurement));
        }

        ArgumentNullException.ThrowIfNull(manifestDigest);
        ArgumentNullException.ThrowIfNull(signature);

        if (manifestDigest.Length == 0)
        {
            throw new ArgumentException(
                "Manifest digest must not be empty.",
                nameof(manifestDigest));
        }

        if (signature.Length == 0)
        {
            throw new ArgumentException(
                "Signature must not be empty.",
                nameof(signature));
        }

        if (expiresAt <= issuedAt)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiresAt),
                "Expiration must be later than issuance.");
        }

        ManifestVersion = manifestVersion;
        CustodyDomain = custodyDomain;
        SecurityBoundaryIdentity = securityBoundaryIdentity;
        VerifierMeasurement = verifierMeasurement;
        PlatformClass = platformClass;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;

        _manifestDigest = (byte[])manifestDigest.Clone();
        _signature = (byte[])signature.Clone();
    }

    public string ManifestVersion { get; }

    public string CustodyDomain { get; }

    public byte[] ManifestDigest => (byte[])_manifestDigest.Clone();

    public string SecurityBoundaryIdentity { get; }

    public string VerifierMeasurement { get; }

    public ConfidentialPlatformClass PlatformClass { get; }

    public DateTimeOffset IssuedAt { get; }

    public DateTimeOffset ExpiresAt { get; }

    public byte[] Signature => (byte[])_signature.Clone();
}