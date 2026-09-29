using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Describes one canonical protected-inventory entry reconstructed from
/// boundary-observed state.
///
/// The entry is evidence about observed state, not authorization.
/// </summary>
public sealed class ProtectedInventoryEntry
{
    private readonly byte[] _sha256;

    internal ProtectedInventoryEntry(
        string relativePath,
        string classification,
        long length,
        byte[] sha256)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
            throw new ArgumentException(
                "Relative path is required.",
                nameof(relativePath));

        if (System.IO.Path.IsPathRooted(relativePath))
            throw new ArgumentException(
                "Protected inventory paths must be relative.",
                nameof(relativePath));

        if (relativePath.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException(
                "Path traversal is prohibited.",
                nameof(relativePath));

        if (string.IsNullOrWhiteSpace(classification))
            throw new ArgumentException(
                "Classification is required.",
                nameof(classification));

        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length));

        ArgumentNullException.ThrowIfNull(sha256);

        if (sha256.Length != 32)
            throw new ArgumentException(
                "Protected entry digest must be SHA-256.",
                nameof(sha256));

        RelativePath = relativePath.Replace('\\', '/');
        Classification = classification;
        Length = length;
        _sha256 = (byte[])sha256.Clone();
    }

    public string RelativePath { get; }

    public string Classification { get; }

    public long Length { get; }

    public byte[] Sha256 => (byte[])_sha256.Clone();
}
