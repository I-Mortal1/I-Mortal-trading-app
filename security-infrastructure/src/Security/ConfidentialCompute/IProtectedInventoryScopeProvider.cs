namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Supplies the protected-inventory scope selected by the confidential
/// security boundary.
///
/// Implementations must not treat caller-provided paths, counts, hashes,
/// classifications, USB possession, or VeraCrypt unlock state as authority.
/// </summary>
public interface IProtectedInventoryScopeProvider
{
    ProtectedInventoryScope GetScope();
}
