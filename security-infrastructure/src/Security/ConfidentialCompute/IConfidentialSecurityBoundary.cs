namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Identifies the confidential-computing security boundary that owns
/// security-sensitive operations. This contract grants no authority.
/// </summary>
public interface IConfidentialSecurityBoundary
{
    ConfidentialSecurityBoundaryIdentity Identity { get; }
}