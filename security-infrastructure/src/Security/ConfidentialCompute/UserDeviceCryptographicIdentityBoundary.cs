namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable architectural boundary for an ordinary user's per-device
/// cryptographic identity.
///
/// ACCOUNT MODEL:
///
/// One I-Mortal user account may contain multiple independently enrolled
/// device cryptographic identities.
///
/// DEVICE KEY MODEL:
///
/// Every enrolled installation/device has its own hardware-protected
/// cryptographic key identity.
///
/// The device private key must remain hardware-backed and non-exportable
/// whenever the platform provides the required approved hardware security
/// capability.
///
/// Private keys are never copied between enrolled devices.
///
/// DEVICE FINGERPRINT MODEL:
///
/// I-Mortal identifies an enrolled device through an application-defined
/// cryptographic fingerprint derived from canonical public identity material
/// and explicit domain/account/platform bindings.
///
/// The fingerprint is not a password, bearer token, private key, login proof,
/// authorization decision, or authority grant.
///
/// Knowledge or possession of a fingerprint alone must never authenticate
/// an account.
///
/// Authentication requires a separate fresh challenge and cryptographic
/// proof-of-possession of the corresponding device private key.
///
/// PLATFORM MODEL:
///
/// Platform-specific providers may subsequently bind the private key to an
/// approved hardware-backed facility, including platform-appropriate TPM,
/// Secure Enclave / secure key facilities, Android hardware-backed Keystore
/// or StrongBox, Linux TPM/security hardware, or future approved equivalents.
///
/// This architectural contract performs no such operation.
///
/// DEVICE-ID PRIVACY MODEL:
///
/// The cryptographic fingerprint must not be defined merely as a raw OS
/// machine identifier, hardware serial number, IMEI, MAC address, TPM serial,
/// motherboard serial, or equivalent invasive/stable hardware identifier.
///
/// Such identifiers must not themselves become reusable authentication
/// credentials.
///
/// DEVELOPER SEPARATION:
///
/// Ordinary-user device cryptographic identities are permanently separate
/// from the I-Mortal developer identity authority chain.
///
/// A user device identity or fingerprint can never replace, emulate, unlock,
/// authorize, or satisfy the developer VeraCrypt USB identity.
///
/// This type performs no key generation, signing, hashing, hardware access,
/// enrollment, authentication, QR processing, network operation, registration,
/// developer USB access, source mutation, TEE activation, attestation
/// activation, or production authorization.
/// </summary>
public static class UserDeviceCryptographicIdentityBoundary
{
    public const string ContractVersion = "1";

    public const string FingerprintDomain =
        "I-MORTAL/USER-DEVICE-FINGERPRINT/V1";

    public const bool OneAccountMayHaveMultipleDevices = true;

    public const bool EveryEnrolledDeviceHasIndependentCryptographicIdentity =
        true;

    public const bool PerDeviceKeyRequired = true;

    public const bool HardwareBackedPrivateKeyRequired = true;

    public const bool NonExportablePrivateKeyRequired = true;

    public const bool PrivateKeyMustRemainOnOriginatingDevice = true;

    public const bool PrivateKeyTransferBetweenDevicesAllowed = false;

    public const bool PrivateKeySynchronizationBetweenDevicesAllowed = false;

    public const bool PrivateKeyDownloadAllowed = false;

    public const bool RawPrivateKeyMayBeAccountIdentifier = false;

    public const bool RawPrivateKeyMayBeDeviceFingerprint = false;

    public const bool PublicCryptographicIdentityRequired = true;

    public const bool CanonicalPublicIdentityRequired = true;

    public const bool DeviceFingerprintRequired = true;

    public const bool FingerprintDomainSeparationRequired = true;

    public const bool FingerprintSchemaVersionBindingRequired = true;

    public const bool FingerprintAccountBindingRequired = true;

    public const bool FingerprintPublicIdentityBindingRequired = true;

    public const bool FingerprintPlatformProviderBindingRequired = true;

    public const bool FingerprintMayContainPrivateKey = false;

    public const bool FingerprintMayContainRawHardwareKeyMaterial = false;

    public const bool FingerprintIsAuthenticationCredential = false;

    public const bool FingerprintIsBearerCredential = false;

    public const bool FingerprintAloneMayAuthenticate = false;

    public const bool FingerprintAloneMayAuthorizeEnrollment = false;

    public const bool FingerprintAloneMayAuthorizeLogin = false;

    public const bool FingerprintAloneMayAuthorizeDeviceRevocation = false;

    public const bool DeviceProofOfPossessionRequiredForAuthentication = true;

    public const bool FreshChallengeRequiredForAuthentication = true;

    public const bool AuthenticationChallengeMustBeSingleUse = true;

    public const bool AuthenticationChallengeMustExpire = true;

    public const bool RawOsMachineIdentifierMayBeFingerprint = false;

    public const bool HardwareSerialNumberMayBeFingerprint = false;

    public const bool ImeiMayBeFingerprint = false;

    public const bool MacAddressMayBeFingerprint = false;

    public const bool MotherboardSerialMayBeFingerprint = false;

    public const bool TpmSerialMayBeFingerprint = false;

    public const bool UserDeviceIdentityMayGrantDeveloperIdentity = false;

    public const bool UserDeviceIdentityMayGrantDeveloperUsbAccess = false;

    public const bool UserDeviceIdentityMayReplaceDeveloperUsb = false;

    public const bool UserDeviceIdentityMayGrantSourceAccess = false;

    public const bool UserDeviceIdentityMayGrantSourceMutation = false;

    public const bool UserDeviceIdentityMayGrantDeveloperSigningAuthority =
        false;

    public const bool UserDeviceIdentityMayGrantTeeAuthority = false;

    public const bool UserDeviceIdentityMayGrantAttestationAuthority = false;

    public const bool UserDeviceIdentityMayGrantProductionAuthority = false;

    public const bool DeveloperVeraCryptUsbRemainsDeveloperOnly = true;

    public const bool KeyGenerationPerformedByThisContract = false;

    public const bool FingerprintCalculationPerformedByThisContract = false;

    public const bool HardwareAccessPerformedByThisContract = false;

    public const bool AuthenticationPerformedByThisContract = false;

    public const bool EnrollmentPerformedByThisContract = false;

    public const bool RegistrationPerformedByThisContract = false;

    public const bool NetworkAccessPerformedByThisContract = false;

    public const bool FailOpenAllowed = false;
}