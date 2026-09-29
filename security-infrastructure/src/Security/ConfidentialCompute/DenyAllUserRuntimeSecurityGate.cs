namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Fail-closed placeholder until the platform-specific user runtime
/// TEE/hardware-backed security composition is connected.
/// </summary>
public sealed class DenyAllUserRuntimeSecurityGate :
    IUserRuntimeSecurityGate
{
    public bool IsSatisfied() => false;
}