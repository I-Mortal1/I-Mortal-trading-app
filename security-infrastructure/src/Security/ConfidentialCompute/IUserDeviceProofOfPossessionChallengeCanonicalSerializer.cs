namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Canonical serializer boundary for an already-established user-device
/// proof-of-possession challenge.
///
/// This interface defines serialization only.
///
/// It does not generate challenges, sign challenges, verify signatures,
/// access private keys, access TPM / Secure Enclave / Android Keystore /
/// Linux TPM facilities, authenticate users, log users in, enroll devices,
/// revoke devices, mutate replay state, grant developer authority, grant
/// source access, grant source-mutation authority, or grant production
/// authorization.
///
/// Implementations must obey
/// UserDeviceProofOfPossessionChallengeCanonicalSerializationContract.
///
/// Device fingerprints identify and bind an enrolled device but are not
/// themselves authentication proof. Authentication requires a fresh,
/// single-use, expiring challenge plus proof of possession produced by the
/// device's independent hardware-backed, non-exportable private key.
///
/// Private key material must never be supplied to this serializer.
/// </summary>
public interface IUserDeviceProofOfPossessionChallengeCanonicalSerializer
{
    byte[] Serialize(
        UserDeviceProofOfPossessionChallengeData challenge);
}