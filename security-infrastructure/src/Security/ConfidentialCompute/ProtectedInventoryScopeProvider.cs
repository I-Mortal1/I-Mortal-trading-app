using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Supplies only the protected inventory scope resolved by the boundary-owned
/// scope authority.
///
/// This provider does not accept caller-selected roots, classifications,
/// filesets, counts, hashes, USB state, or VeraCrypt state. It performs no
/// filesystem enumeration and grants no production authority.
/// </summary>
public sealed class ProtectedInventoryScopeProvider :
    IProtectedInventoryScopeProvider
{
    private readonly IProtectedInventoryScopeAuthority _scopeAuthority;

    public ProtectedInventoryScopeProvider(
        IProtectedInventoryScopeAuthority scopeAuthority)
    {
        _scopeAuthority =
            scopeAuthority ??
            throw new ArgumentNullException(nameof(scopeAuthority));
    }

    public ProtectedInventoryScope GetScope()
    {
        return _scopeAuthority.ResolveAuthoritativeScope()
            ?? throw new InvalidOperationException(
                "Protected inventory scope authority returned no scope.");
    }
}