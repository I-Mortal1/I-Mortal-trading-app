namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Future protected-project access boundary.
///
/// Implementations must evaluate independently established security state.
/// This interface deliberately does not accept caller-asserted booleans such
/// as "attested", "usbAuthenticated", or "authorized".
///
/// A successful evaluation is scoped project access only and must never be
/// interpreted as root trust, production authority, trading authority, or
/// provider-dispatch authority.
/// </summary>
public interface IProtectedProjectAccessGate
{
    bool IsPolicySatisfied(
        ConfidentialSecurityBoundaryIdentity boundaryIdentity,
        EncryptedProjectSigningKeyPolicy policy);
}
