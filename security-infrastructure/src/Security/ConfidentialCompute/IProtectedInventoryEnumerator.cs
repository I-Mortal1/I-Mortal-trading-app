namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Reconstructs the protected project inventory from the security boundary's
/// own observation of project state.
///
/// Caller-asserted inventory counts, hashes, and classifications are not
/// authoritative.
/// </summary>
public interface IProtectedInventoryEnumerator
{
    ProtectedStateSnapshot CaptureCurrent();
}
