namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Provides access to the currently authoritative protected-state identity.
///
/// R15 deliberately exposes no general mutation method. Production state
/// advancement requires a separately controlled confidential commit boundary.
/// </summary>
public interface IProtectedStateRepository
{
    ProtectedStateSnapshot GetCurrent();
}
