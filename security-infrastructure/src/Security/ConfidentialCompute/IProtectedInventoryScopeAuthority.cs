namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Resolves the protected-inventory scope from security-boundary-owned policy.
///
/// Implementations must fail closed. Caller-provided roots, paths, counts,
/// classifications, hashes, USB possession, VeraCrypt unlock state, and
/// historical inventory observations must never become scope authority.
///
/// This interface grants no filesystem, mutation, signing, encryption,
/// attestation, USB, VeraCrypt, deployment, trading, or production authority.
/// </summary>
public interface IProtectedInventoryScopeAuthority
{
    ProtectedInventoryScope ResolveAuthoritativeScope();
}