namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Canonical architectural separation contract between:
///
/// 1. developer cryptographic custody and source-mutation authority; and
/// 2. ordinary finished-application user cryptographic custody.
///
/// This contract grants no authority and performs no cryptographic operation.
///
/// DEVELOPER DOMAIN
/// ----------------
/// The protected developer identity remains bound to the independently
/// authorized VeraCrypt USB custody and developer authorization chain.
///
/// USER DOMAIN
/// -----------
/// Each ordinary application user is restricted to that user's own account,
/// session and application interface.
///
/// User cryptographic key material belongs to a per-user, per-device platform
/// custody domain:
///
/// Windows:
///     TPM 2.0 / Microsoft Platform Crypto Provider.
///
/// macOS:
///     Secure Enclave / Keychain hardware-backed protection where supported.
///
/// iOS:
///     Secure Enclave / Keychain hardware-backed protection where supported.
///
/// Android:
///     Android Keystore / KeyMint, with StrongBox where available.
///
/// Linux:
///     TPM 2.0 hardware-backed protection where supported.
///
/// Platform integration/provider software may be installed and updated as
/// part of the application distribution/update mechanism. Secret user key
/// material itself MUST NOT be distributed with the application or updater.
///
/// A user's device-bound cryptographic key MUST NOT satisfy, replace,
/// impersonate, derive, bypass or weaken any developer VeraCrypt USB,
/// protected-developer-identity, source-mutation, project-signing,
/// approved-workload, project-integrity or TEE authorization requirement.
///
/// Conversely, developer custody MUST NOT become ordinary user account
/// authority.
///
/// The two authority domains are AND-ONLY isolated security domains.
/// </summary>
public static class DeveloperUserCryptographicCustodyBoundary
{
    public const string ContractVersion =
        "R13-ID1-C7-D4-K2";

    // Developer custody domain.
    public const bool DeveloperRequiresProtectedIdentity = true;
    public const bool DeveloperRequiresVeraCryptUsbCustody = true;

    // Ordinary users never inherit developer custody.
    public const bool OrdinaryUserMayUseDeveloperUsb = false;
    public const bool OrdinaryUserMayEnterProtectedDeveloperIdentityChain =
        false;

    // User custody is local to the user's account/device.
    public const bool UserCustodyIsPerUser = true;
    public const bool UserCustodyIsPerDevice = true;
    public const bool UserRuntimeOnly = true;

    // Hardware-backed/non-exportable is the intended finished-user
    // cryptographic custody model.
    public const bool UserHardwareBackedCustodyRequired = true;
    public const bool UserNonExportableKeyRequired = true;

    // Application binaries/provider implementations may be distributed and
    // updated. User secret keys may not.
    public const bool PlatformProviderCodeMayBeDistributed = true;
    public const bool PlatformProviderCodeMayBeUpdated = true;
    public const bool UserSecretKeysMayBeDistributedWithApplication = false;
    public const bool UserSecretKeysMayBeDownloadedByUpdater = false;
    public const bool UserSecretKeysMayBeExportedByApplication = false;

    // No silent downgrade from hardware custody to a software key.
    public const bool SilentSoftwareKeyDowngradeAllowed = false;

    // User platform custody can never become developer authority.
    public const bool UserPlatformKeyMayReplaceDeveloperUsb = false;
    public const bool UserPlatformKeyMaySatisfyDeveloperUsbRequirement =
        false;
    public const bool UserPlatformKeyMayGrantSourceAccess = false;
    public const bool UserPlatformKeyMayGrantSourceMutation = false;
    public const bool UserPlatformKeyMayGrantProjectSigningAuthority = false;
    public const bool UserPlatformKeyMayGrantProjectIntegrityAuthority =
        false;
    public const bool UserPlatformKeyMayGrantApprovedWorkloadAuthority =
        false;
    public const bool UserPlatformKeyMayGrantTeeAuthority = false;
    public const bool UserPlatformKeyMayGrantProductionAuthority = false;

    // Developer authority likewise cannot silently become user-account
    // authorization.
    public const bool DeveloperUsbMayGrantOrdinaryUserAccountAccess = false;

    // Runtime hardware capability must be proven rather than inferred merely
    // from operating-system identity or installed provider code.
    public const bool RuntimeHardwareCapabilityVerificationRequired = true;

    public const bool FailOpenAllowed = false;
}