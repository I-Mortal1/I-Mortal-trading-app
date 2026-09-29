namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Finished-application user-device security boundary.
///
/// This gate is for user runtime protection only. It cannot grant source
/// access, source mutation, developer USB access, developer email-recovery
/// access, production authority, or provider-dispatch authority.
///
/// Implementations may require platform-appropriate hardware-backed key
/// protection and TEE/security-hardware evidence.
/// </summary>
public interface IUserRuntimeSecurityGate
{
    bool IsSatisfied();
}