namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable architectural boundary for ordinary-user multi-device identity.
///
/// ACCOUNT MODEL
///
/// One I-MORTAL user account may be associated with multiple independently
/// enrolled device identities.
///
/// The account identity and a device identity are deliberately distinct.
///
/// A device identity represents one application installation on one physical
/// device and must use its own platform-appropriate cryptographic custody.
///
/// PRIVATE-KEY ISOLATION
///
/// A private device key must never be copied, synchronized, exported,
/// transferred, reconstructed, downloaded, or migrated to another device.
///
/// Adding another device therefore requires that the new device establish its
/// own independent device cryptographic identity.
///
/// Examples include:
///
/// Windows:
///     TPM-backed non-exportable device key.
///
/// Apple platforms:
///     Secure-Enclave-backed device key where supported by platform and
///     security policy.
///
/// Android:
///     hardware-backed Android Keystore / StrongBox where supported by
///     platform and security policy.
///
/// Linux:
///     TPM-backed non-exportable device key where supported by platform and
///     security policy.
///
/// No software-exportable downgrade is implicitly authorized by this
/// contract.
///
/// MULTI-DEVICE ACCOUNT ACCESS
///
/// A user may access the same account from multiple separately enrolled
/// installations.
///
/// A previously authorized device may participate in approving enrollment of
/// a new device.
///
/// Approval of another device does not transfer the approving device's
/// private key.
///
/// The new device must independently prove possession of its own device-bound
/// cryptographic key before it may become an enrolled account device.
///
/// QR PAIRING
///
/// A later protocol may use a QR code to convey a short-lived device-pairing
/// challenge.
///
/// A QR pairing payload must never contain:
///
/// - a private key;
/// - an unwrapped cryptographic key;
/// - a reusable bearer credential;
/// - a recovery secret;
/// - a developer identity secret;
/// - a developer VeraCrypt USB secret;
/// - source-mutation authority material;
/// - production-authority material.
///
/// QR approval and device enrollment are separate from ordinary account login.
///
/// DEVICE EQUALITY
///
/// The first device is not permanently defined as a master cryptographic
/// device.
///
/// After another device has been validly enrolled, account policy may permit
/// that enrolled device to authenticate independently.
///
/// Device enrollment, revocation, recovery, session authorization and
/// account recovery remain separate security protocols.
///
/// DEVELOPER / USER SEPARATION
///
/// Ordinary-user multi-device identity exists exclusively in the finished
/// application user-security domain.
///
/// No ordinary-user device key, QR approval, device enrollment, account
/// ownership, account session, recovery operation or user authentication may:
///
/// - authenticate a developer identity;
/// - replace the developer VeraCrypt USB key;
/// - enter the developer identity chain;
/// - grant access to protected source;
/// - grant source-mutation authority;
/// - grant developer signing authority;
/// - grant TEE authority;
/// - grant attestation authority;
/// - grant production authority.
///
/// The developer VeraCrypt USB mechanism remains a separate developer-only
/// authority domain.
///
/// FAIL-CLOSED
///
/// Absence, ambiguity, invalidity, expiration, replay, cryptographic failure,
/// unsupported platform security, or incomplete device enrollment must never
/// grant device enrollment or account access.
///
/// This type is architectural policy only.
///
/// It performs no cryptographic operation, hardware operation, enrollment,
/// login, QR generation, QR parsing, network operation, key operation,
/// developer operation, source operation or authorization.
/// </summary>
public static class UserMultiDeviceAccountIdentityBoundary
{
    public const int ContractVersion = 1;

    // Account/device identity separation.
    public const bool OneAccountMayHaveMultipleDevices = true;
    public const bool AccountIdentityIsDistinctFromDeviceIdentity = true;
    public const bool EachInstallationHasDistinctDeviceIdentity = true;

    // Device-local key custody.
    public const bool EachDeviceUsesIndependentKey = true;
    public const bool DevicePrivateKeysMustRemainDeviceBound = true;
    public const bool DevicePrivateKeysMustBeNonExportable = true;
    public const bool PrivateKeyTransferBetweenDevicesAllowed = false;
    public const bool PrivateKeySynchronizationAllowed = false;
    public const bool PrivateKeyDownloadAllowed = false;
    public const bool PrivateKeyMigrationAllowed = false;

    // Hardware-backed user custody.
    public const bool HardwareBackedDeviceCustodyRequired = true;
    public const bool SilentSoftwareKeyDowngradeAllowed = false;

    // Multi-device enrollment.
    public const bool ExistingAuthorizedDeviceMayApproveNewDevice = true;
    public const bool NewDeviceMustProveOwnKeyPossession = true;
    public const bool ApprovalTransfersExistingPrivateKey = false;
    public const bool FirstDevicePermanentlyMaster = false;
    public const bool EnrolledDeviceMayLaterAuthenticateIndependently = true;

    // QR architectural boundary.
    public const bool QrPairingArchitecturePermitted = true;
    public const bool QrPayloadMayContainPrivateKey = false;
    public const bool QrPayloadMayContainUnwrappedKey = false;
    public const bool QrPayloadMayContainReusableBearerCredential = false;
    public const bool QrPayloadMayContainRecoverySecret = false;
    public const bool QrPayloadMayContainDeveloperSecret = false;
    public const bool QrPayloadMayContainDeveloperUsbSecret = false;
    public const bool QrPayloadMayContainSourceMutationAuthority = false;
    public const bool QrPayloadMayContainProductionAuthority = false;

    // Protocol separation.
    public const bool DeviceEnrollmentIsLogin = false;
    public const bool DeviceEnrollmentIsAccountRecovery = false;
    public const bool DeviceEnrollmentIsDeveloperAuthentication = false;
    public const bool DeviceRevocationIsSeparateProtocol = true;
    public const bool AccountRecoveryIsSeparateProtocol = true;

    // User/developer separation.
    public const bool UserDeviceCanAuthenticateDeveloper = false;
    public const bool UserDeviceCanReplaceDeveloperUsb = false;
    public const bool UserDeviceCanEnterDeveloperIdentityChain = false;
    public const bool UserDeviceCanGrantSourceAccess = false;
    public const bool UserDeviceCanGrantSourceMutation = false;
    public const bool UserDeviceCanGrantDeveloperSigning = false;
    public const bool UserDeviceCanGrantTeeAuthority = false;
    public const bool UserDeviceCanGrantAttestationAuthority = false;
    public const bool UserDeviceCanGrantProductionAuthority = false;

    // Fail-closed requirements.
    public const bool ExpiredPairingChallengeAccepted = false;
    public const bool ReplayedPairingChallengeAccepted = false;
    public const bool AmbiguousPairingChallengeAccepted = false;
    public const bool InvalidCryptographicProofAccepted = false;
    public const bool IncompleteDeviceEnrollmentAccepted = false;
    public const bool UnsupportedHardwareSecurityFailsOpen = false;

    // This contract activates nothing.
    public const bool PerformsKeyGeneration = false;
    public const bool PerformsKeyProvisioning = false;
    public const bool PerformsKeyUnwrap = false;
    public const bool PerformsRawKeyAccess = false;
    public const bool PerformsQrGeneration = false;
    public const bool PerformsQrParsing = false;
    public const bool PerformsDeviceEnrollment = false;
    public const bool PerformsLogin = false;
    public const bool PerformsNetworkAccess = false;
    public const bool PerformsDeveloperUsbAccess = false;
    public const bool PerformsSourceMutation = false;
    public const bool GrantsProductionAuthority = false;
}