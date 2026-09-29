namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable data contract for one user-device proof-of-possession challenge.
///
/// This type carries challenge data only.
///
/// It performs no:
/// - challenge generation,
/// - challenge signing,
/// - signature verification,
/// - authentication,
/// - login authorization,
/// - device enrollment,
/// - device revocation,
/// - QR generation,
/// - QR scanning,
/// - network I/O,
/// - TPM access,
/// - Secure Enclave access,
/// - Android Keystore access,
/// - Linux TPM access,
/// - private-key access,
/// - developer USB access,
/// - source mutation,
/// - TEE activation,
/// - production authorization.
///
/// The device fingerprint is an identifier and binding value only.
/// It is not authentication proof.
///
/// Authentication requires independent proof of possession of the enrolled
/// device's hardware-backed, non-exportable private key.
///
/// Challenge processing belongs to the I-Mortal confidential identity plane.
///
/// A challenge must be fresh, single-use, expiring, account-bound,
/// device-bound, purpose-bound, and protocol-bound.
///
/// Replay acceptance is forbidden.
/// </summary>
public sealed record UserDeviceProofOfPossessionChallengeData(
    string ContractVersion,
    string ProtocolId,
    string ChallengeId,
    string ChallengeNonce,
    string AccountIdentity,
    string DeviceFingerprint,
    string AuthenticationPurpose,
    long IssuedAtUnixTimeSeconds,
    long ExpiresAtUnixTimeSeconds)
{
    public const string CurrentContractVersion = "1";

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE/PROOF-OF-POSSESSION/CHALLENGE/V1";

    public const bool ContainsPrivateKeyMaterial = false;

    public const bool FingerprintIsAuthenticationProof = false;

    public const bool HardwareKeyProofOfPossessionRequired = true;

    public const bool FreshChallengeRequired = true;

    public const bool SingleUseRequired = true;

    public const bool ExpirationRequired = true;

    public const bool ReplayAcceptanceAllowed = false;

    public const bool AccountBindingRequired = true;

    public const bool DeviceBindingRequired = true;

    public const bool PurposeBindingRequired = true;

    public const bool ProtocolBindingRequired = true;

    public const bool ConfidentialIdentityPlaneRequired = true;

    public const bool AttestedServerIdentityRequired = true;

    public const bool GrantsDeveloperSourceAccess = false;

    public const bool GrantsDeveloperUsbAuthority = false;

    public const bool GrantsSourceMutationAuthority = false;

    public const bool GrantsProductionAuthorization = false;

    public const bool FailOpenAllowed = false;

    public const bool DefaultAuthorizationDecision = false;
}