namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Architectural contract for an ordinary user's enrolled device
/// cryptographic proof-of-possession.
///
/// This contract defines requirements only. It performs no cryptographic
/// operation, key access, signing, verification, authentication, enrollment,
/// QR processing, hardware access, attestation, or authority activation.
///
/// Account model:
///
///     one user account
///         -> one or more independently enrolled devices
///         -> one independent hardware-backed non-exportable private key
///            per device
///         -> one I-Mortal cryptographic device fingerprint per device.
///
/// A device fingerprint identifies and binds an enrolled public device
/// identity. The fingerprint itself is not authentication evidence.
///
/// Authentication requires fresh proof that the claimant controls the
/// private key corresponding to the enrolled public key.
///
/// The private key remains local to the device security boundary and is
/// never copied between devices.
///
/// This ordinary-user mechanism cannot grant developer source access,
/// developer source mutation authority, developer VeraCrypt USB authority,
/// software-signing authority, TEE administrative authority, or production
/// authorization.
/// </summary>
public static class UserDeviceProofOfPossessionContract
{
    public const int ContractVersion = 1;

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE-PROOF-OF-POSSESSION/V1";

    /*
     * Identity and key custody.
     */

    public const bool OneIndependentPrivateKeyPerDevice = true;

    public const bool DevicePrivateKeyMustBeHardwareBacked = true;

    public const bool DevicePrivateKeyMustBeNonExportable = true;

    public const bool DevicePrivateKeyTransferForbidden = true;

    public const bool DevicePrivateKeySynchronizationForbidden = true;

    public const bool PrivateKeyMustRemainInsideDeviceSecurityBoundary = true;

    /*
     * Device fingerprint semantics.
     */

    public const bool DeviceFingerprintRequired = true;

    public const bool DeviceFingerprintIsIdentificationOnly = true;

    public const bool DeviceFingerprintIsNotAuthenticationProof = true;

    public const bool DeviceFingerprintCannotReplaceProofOfPossession = true;

    /*
     * Challenge requirements.
     */

    public const bool FreshChallengeRequired = true;

    public const bool ChallengeMustBeSingleUse = true;

    public const bool ChallengeMustExpire = true;

    public const bool ChallengeReplayForbidden = true;

    public const bool ChallengeMustBeBoundToAccount = true;

    public const bool ChallengeMustBeBoundToDeviceFingerprint = true;

    public const bool ChallengeMustBeBoundToAuthenticationPurpose = true;

    public const bool ChallengeMustBeBoundToProtocolVersion = true;

    public const bool ChallengeMustBeServerOriginated = true;

    /*
     * Proof requirements.
     */

    public const bool ProofMustUseDevicePrivateKey = true;

    public const bool ProofMustVerifyAgainstEnrolledPublicKey = true;

    public const bool ProofMustCoverExactChallenge = true;

    public const bool ProofMustCoverAccountBinding = true;

    public const bool ProofMustCoverDeviceFingerprintBinding = true;

    public const bool ProofMustCoverPurposeBinding = true;

    public const bool ProofMustCoverProtocolVersionBinding = true;

    public const bool InvalidProofMustFailClosed = true;

    public const bool MissingProofMustFailClosed = true;

    public const bool UnknownDeviceMustFailClosed = true;

    public const bool RevokedDeviceMustFailClosed = true;

    public const bool ExpiredChallengeMustFailClosed = true;

    public const bool ReplayedChallengeMustFailClosed = true;

    public const bool AccountMismatchMustFailClosed = true;

    public const bool DeviceFingerprintMismatchMustFailClosed = true;

    /*
     * Multi-device architecture.
     */

    public const bool ExistingDeviceMayAuthorizeNewDeviceEnrollment = true;

    public const bool NewDeviceMustCreateIndependentKey = true;

    public const bool ExistingDevicePrivateKeyMustNotBeCopied = true;

    public const bool NewDeviceMustReceiveIndependentFingerprint = true;

    public const bool EachDeviceMustProveItsOwnKeyPossession = true;

    /*
     * Cross-platform custody model.
     *
     * These constants describe the required security class only.
     * They do not invoke any platform API.
     */

    public const bool WindowsHardwareCustodyRequired = true;

    public const bool AppleHardwareCustodyRequired = true;

    public const bool AndroidHardwareCustodyRequired = true;

    public const bool LinuxHardwareCustodyRequired = true;

    /*
     * Confidential identity plane.
     *
     * Registration, login, authentication, and device enrollment are
     * intended to be processed behind the I-Mortal confidential-computing
     * identity boundary. This contract does not activate that boundary.
     */

    public const bool ConfidentialIdentityPlaneRequired = true;

    public const bool AttestedServerIdentityRequired = true;

    public const bool RegistrationMustUseConfidentialIdentityPlane = true;

    public const bool LoginMustUseConfidentialIdentityPlane = true;

    public const bool DeviceEnrollmentMustUseConfidentialIdentityPlane = true;

    public const bool ProofVerificationMustUseConfidentialIdentityPlane = true;

    /*
     * Developer/user authority separation.
     */

    public const bool UserProofCannotGrantDeveloperSourceAccess = true;

    public const bool UserProofCannotGrantDeveloperSourceMutation = true;

    public const bool UserProofCannotGrantDeveloperUsbAuthority = true;

    public const bool UserProofCannotGrantDeveloperIdentityAuthority = true;

    public const bool UserProofCannotGrantSoftwareSigningAuthority = true;

    public const bool UserProofCannotGrantTeeAdministrativeAuthority = true;

    public const bool UserProofCannotGrantProductionAuthorization = true;

    /*
     * Fail-closed invariant.
     */

    public const bool FailOpenForbidden = true;

    public const bool DefaultDecisionDeny = true;
}