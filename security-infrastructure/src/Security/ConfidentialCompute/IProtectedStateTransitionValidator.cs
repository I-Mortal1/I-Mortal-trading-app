namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Validation boundary for a proposed protected-state transition.
///
/// Returning true is not root trust, source authority, signing authority,
/// trading authority, provider-dispatch authority, or production authority.
/// </summary>
public interface IProtectedStateTransitionValidator
{
    bool Validate(
        ProtectedStateTransition transition,
        ConfidentialSecurityBoundaryIdentity boundaryIdentity);
}
