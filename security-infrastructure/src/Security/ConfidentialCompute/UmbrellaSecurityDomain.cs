namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Distinguishes finished-application user security from developer
/// source-custody security.
///
/// User runtime authority must never imply developer/source authority.
/// </summary>
public enum UmbrellaSecurityDomain
{
    None = 0,

    /// <summary>
    /// Installed finished application. No source access or source mutation.
    /// </summary>
    UserRuntime = 1,

    /// <summary>
    /// Developer-only protected source-custody domain.
    /// </summary>
    DeveloperSourceCustody = 2
}