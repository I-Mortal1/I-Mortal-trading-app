namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Safe placeholder.
///
/// It deliberately provides neither USB nor email-recovery authority.
/// </summary>
public sealed class DenyAllDeveloperSourceAuthorityGate :
    IDeveloperSourceAuthorityGate
{
    public bool IsSatisfied(
        DeveloperSourceAuthorityMode mode)
        => false;
}