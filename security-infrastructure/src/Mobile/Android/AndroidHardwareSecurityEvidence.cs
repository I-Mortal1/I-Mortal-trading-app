namespace IMortal.TrustBroker.Mobile.Android;

/// <summary>
/// Normalized Android hardware-security evidence.
///
/// This enum represents normalized evidence only.
/// It does not create keys, invoke Android APIs, perform attestation,
/// or authorize production use.
/// </summary>
public enum AndroidHardwareSecurityEvidence
{
    /// <summary>
    /// Hardware-security evidence could not be established.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// The reported security implementation is software-only.
    /// </summary>
    SoftwareOnly = 1,

    /// <summary>
    /// The reported key protection is backed by the Android
    /// trusted execution environment.
    /// </summary>
    TrustedExecutionEnvironment = 2,

    /// <summary>
    /// The reported key protection is backed by Android StrongBox.
    /// </summary>
    StrongBox = 3
}
