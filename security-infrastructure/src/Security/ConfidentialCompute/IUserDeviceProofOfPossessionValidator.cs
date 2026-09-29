namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Interface contract for the future user-device proof-of-possession
/// validator inside the I-Mortal confidential identity plane.
///
/// The interface describes validation inputs and a non-authoritative result.
/// It does not itself implement or execute validation.
///
/// Implementations must fail closed and must execute only behind the
/// approved I-Mortal TEE / TDX / SEV-SNP confidential-computing boundary
/// after required attestation and approved-workload checks.
///
/// DeviceFingerprint is identification and binding data only.
/// It is not authentication proof.
///
/// Authentication requires independent proof of possession of the enrolled
/// device's hardware-backed, non-exportable private key.
///
/// A successful validation result does not itself authenticate a user,
/// authorize login, authorize enrollment, grant developer authority,
/// grant source-mutation authority, or grant production authorization.
/// A separate fail-closed authentication-policy evaluation is required.
/// </summary>
public interface IUserDeviceProofOfPossessionValidator
{
    UserDeviceProofOfPossessionValidationResultData Validate(
        UserDeviceProofOfPossessionChallengeData challenge,
        UserDeviceProofOfPossessionSignatureData signature,
        string enrolledAccountIdentity,
        string enrolledDeviceFingerprint,
        string enrolledPublicKeyAlgorithm,
        string enrolledPublicKeyIdentity,
        byte[] enrolledCanonicalPublicKey,
        bool enrolledDeviceActive,
        bool hardwareBackedKeyRequired,
        bool nonExportableKeyRequired,
        bool challengeKnown,
        bool challengeUnused,
        bool challengeFresh,
        bool challengeNotExpired,
        bool replayStateValid,
        string expectedAuthenticationPurpose,
        string expectedProtocolId,
        bool attestationPresent,
        bool attestationFresh,
        bool attestationPolicyValid,
        bool approvedWorkloadIdentityValid,
        bool approvedMeasurementValid,
        bool teeValidationBoundarySatisfied);
}