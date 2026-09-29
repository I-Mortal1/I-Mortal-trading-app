namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Mutually exclusive developer source-custody authentication modes.
///
/// This enum selects a mode only. It grants no authority.
/// </summary>
public enum DeveloperSourceAuthorityMode
{
    None = 0,

    /// <summary>
    /// Normal developer path using the authorized VeraCrypt USB source root.
    /// </summary>
    NormalUsb = 1,

    /// <summary>
    /// Recovery path permitted only when the USB is unavailable and the
    /// separately controlled email-verification protocol succeeds.
    /// </summary>
    UsbUnavailableEmailRecovery = 2
}