using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Describes the boundary-owned scope from which a protected inventory may
/// subsequently be reconstructed.
///
/// This object is descriptive only. It does not enumerate the filesystem,
/// authorize access, establish a protected baseline, or grant mutation,
/// signing, attestation, USB, VeraCrypt, or production authority.
/// </summary>
public sealed class ProtectedInventoryScope
{
    internal ProtectedInventoryScope(
        string scopeIdentifier,
        string canonicalRootIdentifier,
        string classification)
    {
        if (string.IsNullOrWhiteSpace(scopeIdentifier))
            throw new ArgumentException(
                "Scope identifier is required.",
                nameof(scopeIdentifier));

        if (string.IsNullOrWhiteSpace(canonicalRootIdentifier))
            throw new ArgumentException(
                "Canonical root identifier is required.",
                nameof(canonicalRootIdentifier));

        if (System.IO.Path.IsPathRooted(canonicalRootIdentifier))
            throw new ArgumentException(
                "Host-specific absolute roots are prohibited.",
                nameof(canonicalRootIdentifier));

        if (canonicalRootIdentifier.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException(
                "Path traversal is prohibited.",
                nameof(canonicalRootIdentifier));

        if (string.IsNullOrWhiteSpace(classification))
            throw new ArgumentException(
                "Scope classification is required.",
                nameof(classification));

        ScopeIdentifier = scopeIdentifier;
        CanonicalRootIdentifier =
            canonicalRootIdentifier.Replace('\\', '/');
        Classification = classification;
    }

    public string ScopeIdentifier { get; }

    public string CanonicalRootIdentifier { get; }

    public string Classification { get; }
}
