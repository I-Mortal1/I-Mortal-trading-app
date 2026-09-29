using System;
using System.Collections.Generic;
using System.Linq;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Represents a canonical, boundary-observed protected inventory.
///
/// Construction is restricted to the assembly. Possession does not authorize
/// baseline promotion or any security-sensitive operation.
/// </summary>
public sealed class ProtectedInventoryEnumeration
{
    private readonly ProtectedInventoryEntry[] _entries;
    private readonly byte[] _canonicalStateDigest;

    internal ProtectedInventoryEnumeration(
        ProtectedInventoryScope scope,
        IReadOnlyList<ProtectedInventoryEntry> entries,
        byte[] canonicalStateDigest)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(canonicalStateDigest);

        if (entries.Count == 0)
            throw new ArgumentException(
                "Protected inventory must contain at least one entry.",
                nameof(entries));

        if (canonicalStateDigest.Length != 32)
            throw new ArgumentException(
                "Canonical state digest must be SHA-256.",
                nameof(canonicalStateDigest));

        var copy = entries.ToArray();

        if (copy.Any(static entry => entry is null))
            throw new ArgumentException(
                "Protected inventory entries must not contain null.",
                nameof(entries));

        for (var index = 1; index < copy.Length; index++)
        {
            var comparison = StringComparer.Ordinal.Compare(
                copy[index - 1].RelativePath,
                copy[index].RelativePath);

            if (comparison >= 0)
                throw new ArgumentException(
                    "Protected entries must be unique and ordered by ordinal relative path.",
                    nameof(entries));
        }

        _entries = copy;
        _canonicalStateDigest = (byte[])canonicalStateDigest.Clone();
    }

    public ProtectedInventoryScope Scope { get; }

    public int Count => _entries.Length;

    public IReadOnlyList<ProtectedInventoryEntry> Entries =>
        Array.AsReadOnly(_entries);

    public byte[] CanonicalStateDigest =>
        (byte[])_canonicalStateDigest.Clone();
}
