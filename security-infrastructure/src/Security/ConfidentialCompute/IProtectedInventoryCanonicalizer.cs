using System.Collections.Generic;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Canonicalizes boundary-observed protected entries and derives the canonical
/// state digest.
///
/// Implementations must use deterministic ordinal path ordering and must bind
/// path, classification, length, and SHA-256 using an unambiguous encoding.
/// </summary>
public interface IProtectedInventoryCanonicalizer
{
    ProtectedInventoryEnumeration Canonicalize(
        ProtectedInventoryScope scope,
        IReadOnlyList<ProtectedInventoryEntry> observedEntries);
}
