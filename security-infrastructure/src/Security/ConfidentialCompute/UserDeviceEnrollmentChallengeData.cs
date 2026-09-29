using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable data representation for a short-lived, single-use,
/// multi-device enrollment challenge.
///
/// SECURITY BOUNDARY:
///
/// This type is data only.
///
/// It does not:
/// - generate cryptographic randomness,
/// - generate or scan QR codes,
/// - access hardware-backed private keys,
/// - access TPM / Secure Enclave / Android Keystore / Linux TPM,
/// - perform proof-of-possession,
/// - approve a requesting device,
/// - authenticate an account,
/// - enroll or revoke a device,
/// - perform network operations,
/// - access developer VeraCrypt / USB material,
/// - grant source access,
/// - grant source mutation authority,
/// - grant signing authority,
/// - grant TEE or attestation authority,
/// - grant production authority.
///
/// Account identity and device identity remain distinct.
///
/// No private key, raw hardware key material, reusable bearer credential,
/// developer secret, or developer USB secret may be represented by this
/// contract.
/// </summary>
public sealed record UserDeviceEnrollmentChallengeData(
    string ProtocolVersion,
    string ChallengeId,
    string AccountId,
    string RequestingDeviceId,
    byte[] RequestingDevicePublicKeyDigest,
    byte[] ChallengeNonce,
    string IntendedOperation,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc)
{
    public const string ContractVersion = "1";

    public const bool DataOnly = true;

    public const bool AccountIdentityDistinctFromDeviceIdentity = true;

    public const bool AccountBindingRequired = true;

    public const bool RequestingDeviceBindingRequired = true;

    public const bool RequestingDevicePublicKeyDigestBindingRequired = true;

    public const bool CryptographicNonceRequired = true;

    public const bool IntendedOperationBindingRequired = true;

    public const bool CreationTimeRequired = true;

    public const bool ExpirationTimeRequired = true;

    public const bool ShortLivedRequired = true;

    public const bool SingleUseRequired = true;

    public const bool RequestingDeviceProofOfPossessionRequired = true;

    public const bool ExistingAuthorizedDeviceApprovalRequired = true;

    public const bool PrivateKeyTransferAllowed = false;

    public const bool PrivateKeySynchronizationAllowed = false;

    public const bool PrivateKeyDownloadAllowed = false;

    public const bool PrivateKeyMayBeContained = false;

    public const bool RawHardwareKeyMaterialMayBeContained = false;

    public const bool ReusableBearerCredentialMayBeContained = false;

    public const bool DeveloperSecretMayBeContained = false;

    public const bool DeveloperUsbSecretMayBeContained = false;

    public const bool QrPossessionAloneMayAuthorizeEnrollment = false;

    public const bool QrPossessionAloneMayAuthenticateAccount = false;

    public const bool DeviceEnrollmentEqualsAccountLogin = false;

    public const bool DeviceEnrollmentMayGrantDeveloperIdentity = false;

    public const bool DeviceEnrollmentMayGrantDeveloperUsbAccess = false;

    public const bool DeviceEnrollmentMayGrantSourceAccess = false;

    public const bool DeviceEnrollmentMayGrantSourceMutation = false;

    public const bool DeviceEnrollmentMayGrantSigningAuthority = false;

    public const bool DeviceEnrollmentMayGrantTeeAuthority = false;

    public const bool DeviceEnrollmentMayGrantAttestationAuthority = false;

    public const bool DeviceEnrollmentMayGrantProductionAuthority = false;

    public const bool FailOpenAllowed = false;
}