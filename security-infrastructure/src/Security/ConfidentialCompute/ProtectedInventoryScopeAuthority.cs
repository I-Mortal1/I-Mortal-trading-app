namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Boundary-owned immutable policy for the protected inventory scope.
///
/// The scope identifier, canonical root identifier, and classification are
/// security policy. They are not derived from caller input, environment
/// variables, command-line arguments, working directory, observed file counts,
/// historical inventory counts, USB possession, or VeraCrypt unlock state.
///
/// This class performs no filesystem enumeration and grants no mutation,
/// cryptographic, attestation, USB, VeraCrypt, deployment, trading, or
/// production authority.
/// </summary>
public sealed class ProtectedInventoryScopeAuthority :
    IProtectedInventoryScopeAuthority
{
    private const string ScopeIdentifier =
        "I-Mortal-trustbroker-confidential-security-boundary-v1";

    private const string CanonicalRootIdentifier =
        "Security/ConfidentialCompute";

    private const string Classification =
        "restricted";

    public ProtectedInventoryScope ResolveAuthoritativeScope()
    {
        return new ProtectedInventoryScope(
            ScopeIdentifier,
            CanonicalRootIdentifier,
            Classification);
    }
}