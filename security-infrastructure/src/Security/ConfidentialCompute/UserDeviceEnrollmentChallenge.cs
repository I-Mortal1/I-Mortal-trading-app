namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Architectural security contract for an ordinary-user multi-device
/// enrollment challenge.
///
/// This contract defines required properties only.
///
/// It performs no:
///
/// - key generation;
/// - key provisioning;
/// - key unwrap;
/// - raw-key access;
/// - TPM access;
/// - Secure Enclave access;
/// - Android Keystore access;
/// - Linux TPM access;
/// - QR generation;
/// - QR scanning;
/// - network operation;
/// - login;
/// - enrollment;
/// - registration;
/// - signing;
/// - developer USB operation;
/// - source access;
/// - source mutation;
/// - TEE activation;
/// - attestation activation; or
/// - production authorization.
///
/// ACCOUNT / DEVICE MODEL
/// ----------------------
///
/// A user account may be used from multiple independently enrolled
/// installations.
///
/// Account identity and device identity remain separate.
///
/// Every installation must have its own independent device identity and
/// its own hardware-backed, non-exportable private key.
///
/// A private key belonging to one device must never be transferred,
/// synchronized, downloaded, copied, or embedded into a QR code for another
/// device.
///
/// CROSS-DEVICE ENROLLMENT MODEL
/// -----------------------------
///
/// A new installation creates or possesses its own independent device
/// identity.
///
/// A later implementation may represent a short-lived enrollment challenge
/// as a QR code.
///
/// The QR representation is not authority.
///
/// Possession of the QR representation alone cannot:
///
/// - authenticate the account;
/// - enroll the requesting device;
/// - transfer an existing device identity;
/// - transfer a private key; or
/// - grant any developer authority.
///
/// Successful device enrollment requires independent evidence from both:
///
/// 1. the requesting device, proving possession of its own private key; and
///
/// 2. an already-authorized account device, explicitly approving the
///    requesting device.
///
/// The enrollment challenge must be:
///
/// - protocol-version bound;
/// - uniquely identified;
/// - account bound;
/// - requesting-device bound;
/// - requesting-public-key bound;
/// - operation bound;
/// - nonce bound;
/// - time bounded;
/// - short lived;
/// - single use; and
/// - replay resistant.
///
/// DEVELOPER AUTHORITY SEPARATION
/// ------------------------------
///
/// This contract belongs exclusively to the ordinary-user account/device
/// security domain.
///
/// It cannot grant:
///
/// - developer identity;
/// - developer VeraCrypt USB access;
/// - source access;
/// - source mutation;
/// - signing authority;
/// - TEE authority;
/// - attestation authority;
/// - provider-dispatch authority; or
/// - production authority.
///
/// The developer VeraCrypt USB security chain remains a completely separate
/// authority domain.
///
/// All later implementations must fail closed.
/// </summary>
public static class UserDeviceEnrollmentChallenge
{
    public const int ContractVersion = 1;

    public const string IntendedOperation =
        "USER_DEVICE_ENROLLMENT";

    // -----------------------------------------------------------------
    // ACCOUNT / DEVICE IDENTITY SEPARATION
    // -----------------------------------------------------------------

    public const bool
        AccountIdentityMustRemainDistinctFromDeviceIdentity =
        true;

    public const bool
        RequestingInstallationMustHaveDistinctDeviceIdentity =
        true;

    // -----------------------------------------------------------------
    // PER-DEVICE KEY CUSTODY
    // -----------------------------------------------------------------

    public const bool
        RequestingDeviceMustHaveIndependentPrivateKey =
        true;

    public const bool
        RequestingDevicePrivateKeyMustBeHardwareBacked =
        true;

    public const bool
        RequestingDevicePrivateKeyMustBeNonExportable =
        true;

    public const bool
        ExistingDevicePrivateKeyMustRemainOnExistingDevice =
        true;

    public const bool
        PrivateKeyTransferBetweenDevicesAllowed =
        false;

    public const bool
        PrivateKeySynchronizationBetweenDevicesAllowed =
        false;

    public const bool
        PrivateKeyDownloadAllowed =
        false;

    // -----------------------------------------------------------------
    // CHALLENGE BINDING
    // -----------------------------------------------------------------

    public const bool
        ChallengeMustContainProtocolVersion =
        true;

    public const bool
        ChallengeMustContainUniqueChallengeIdentifier =
        true;

    public const bool
        ChallengeMustBeAccountBound =
        true;

    public const bool
        ChallengeMustBindRequestingDeviceIdentifier =
        true;

    public const bool
        ChallengeMustBindRequestingDevicePublicKeyDigest =
        true;

    public const bool
        ChallengeMustContainCryptographicNonce =
        true;

    public const bool
        ChallengeMustBindIntendedOperation =
        true;

    public const bool
        ChallengeMustContainCreationTime =
        true;

    public const bool
        ChallengeMustContainExpirationTime =
        true;

    public const bool
        CryptographicallySecureChallengeEntropyRequired =
        true;

    // -----------------------------------------------------------------
    // QR SECURITY BOUNDARY
    // -----------------------------------------------------------------

    public const bool
        QrMayRepresentShortLivedEnrollmentChallenge =
        true;

    public const bool
        QrPossessionAloneMayAuthorizeEnrollment =
        false;

    public const bool
        QrPossessionAloneMayAuthenticateAccount =
        false;

    public const bool
        QrMayContainDevicePrivateKey =
        false;

    public const bool
        QrMayContainReusableBearerCredential =
        false;

    public const bool
        QrMayContainRawHardwareKeyMaterial =
        false;

    public const bool
        QrMayContainDeveloperSecret =
        false;

    public const bool
        QrMayContainDeveloperUsbSecret =
        false;

    // -----------------------------------------------------------------
    // REQUESTING-DEVICE PROOF
    // -----------------------------------------------------------------

    public const bool
        RequestingDeviceProofOfPossessionRequired =
        true;

    public const bool
        RequestingDeviceProofMustBindChallengeIdentifier =
        true;

    public const bool
        RequestingDeviceProofMustBindAccount =
        true;

    public const bool
        RequestingDeviceProofMustBindDeviceIdentifier =
        true;

    public const bool
        RequestingDeviceProofMustBindPublicKey =
        true;

    public const bool
        RequestingDeviceProofMustBindOperation =
        true;

    // -----------------------------------------------------------------
    // EXISTING AUTHORIZED DEVICE APPROVAL
    // -----------------------------------------------------------------

    public const bool
        ExistingAuthorizedDeviceApprovalRequired =
        true;

    public const bool
        ExistingDeviceApprovalMustBeExplicit =
        true;

    public const bool
        ExistingDeviceApprovalMustBeCryptographicallyBound =
        true;

    public const bool
        ExistingDeviceApprovalMustBindChallengeIdentifier =
        true;

    public const bool
        ExistingDeviceApprovalMustBindAccount =
        true;

    public const bool
        ExistingDeviceApprovalMustBindRequestingDevice =
        true;

    public const bool
        ExistingDeviceApprovalMustBindRequestingPublicKey =
        true;

    public const bool
        ExistingDeviceApprovalMustBindOperation =
        true;

    // -----------------------------------------------------------------
    // ANTI-REPLAY / CHALLENGE LIFECYCLE
    // -----------------------------------------------------------------

    public const bool
        ChallengeMustBeShortLived =
        true;

    public const bool
        ChallengeMustBeSingleUse =
        true;

    public const bool
        ExpiredChallengeMustBeRejected =
        true;

    public const bool
        ConsumedChallengeMustBeRejected =
        true;

    public const bool
        UnknownChallengeMustBeRejected =
        true;

    public const bool
        AccountMismatchMustBeRejected =
        true;

    public const bool
        DeviceIdentifierMismatchMustBeRejected =
        true;

    public const bool
        PublicKeyMismatchMustBeRejected =
        true;

    public const bool
        OperationMismatchMustBeRejected =
        true;

    public const bool
        InvalidRequestingDeviceProofMustBeRejected =
        true;

    public const bool
        InvalidExistingDeviceApprovalMustBeRejected =
        true;

    // -----------------------------------------------------------------
    // ENROLLMENT SEMANTICS
    // -----------------------------------------------------------------

    public const bool
        SuccessfulChallengeValidationMayPermitDeviceEnrollment =
        true;

    public const bool
        DeviceEnrollmentEqualsAccountLogin =
        false;

    public const bool
        DeviceEnrollmentTransfersExistingDeviceAuthority =
        false;

    public const bool
        FirstDeviceIsPermanentMaster =
        false;

    // -----------------------------------------------------------------
    // DEVELOPER / USER AUTHORITY SEPARATION
    // -----------------------------------------------------------------

    public const bool
        UserEnrollmentMayGrantDeveloperIdentity =
        false;

    public const bool
        UserEnrollmentMayGrantDeveloperUsbAccess =
        false;

    public const bool
        UserEnrollmentMayGrantSourceAccess =
        false;

    public const bool
        UserEnrollmentMayGrantSourceMutation =
        false;

    public const bool
        UserEnrollmentMayGrantSigningAuthority =
        false;

    public const bool
        UserEnrollmentMayGrantTeeAuthority =
        false;

    public const bool
        UserEnrollmentMayGrantAttestationAuthority =
        false;

    public const bool
        UserEnrollmentMayGrantProductionAuthority =
        false;

    // -----------------------------------------------------------------
    // FAIL-CLOSED INVARIANTS
    // -----------------------------------------------------------------

    public const bool
        MissingRequiredBindingMustFail =
        true;

    public const bool
        AmbiguousChallengeMustFail =
        true;

    public const bool
        UnsupportedProtocolVersionMustFail =
        true;

    public const bool
        FailOpenAllowed =
        false;
}