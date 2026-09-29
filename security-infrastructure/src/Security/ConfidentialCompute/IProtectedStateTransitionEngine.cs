namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Defines the confidential protected-state transition boundary.
///
/// Implementations must fail closed. Preparation does not authorize or commit
/// a state transition. Production commit semantics require the independent
/// confidential-compute, USB/VeraCrypt, signing-capability, and project-policy
/// gates defined by the I-MORTAL security architecture.
/// </summary>
public interface IProtectedStateTransitionEngine
{
    PreparedProtectedStateTransition Prepare(
        ProtectedStateTransition transition);

    bool Validate(
        PreparedProtectedStateTransition preparedTransition);
}
