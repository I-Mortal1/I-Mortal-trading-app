namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Developer-only source-custody authority boundary.
///
/// Implementations must independently establish all evidence required by
/// the selected mode.
///
/// NormalUsb requires the complete VeraCrypt/USB source-custody chain.
///
/// UsbUnavailableEmailRecovery requires the complete independently
/// controlled recovery chain.
///
/// A successful result remains scoped source-custody authority and does not
/// itself grant production, trading, provider-dispatch, or root authority.
/// </summary>
public interface IDeveloperSourceAuthorityGate
{
    bool IsSatisfied(
        DeveloperSourceAuthorityMode mode);
}