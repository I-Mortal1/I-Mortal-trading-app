namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Architectural contract for the I-Mortal user-device cryptographic
/// fingerprint digest.
///
/// The fingerprint is derived from deterministic public device-identity
/// canonical serialization.
///
/// This contract performs no hashing, key access, registration, enrollment,
/// authentication, login, QR processing, network access, attestation,
/// developer authorization, source authorization, or production
/// authorization.
///
/// Each enrolled user device retains its own hardware-backed,
/// non-exportable private key. Private keys are never synchronized,
/// transferred, copied, or exported between user devices.
///
/// A fingerprint identifies and binds an enrolled public device identity.
/// It is not an authentication secret.
///
/// Authentication must independently require a fresh challenge and
/// proof-of-possession by the corresponding hardware-protected private key.
///
/// User-device identity remains completely separate from the developer
/// VeraCrypt USB authority chain.
/// </summary>
public static class UserDeviceFingerprintDigestContract
{
    public const int ContractVersion = 1;

    public const string DigestAlgorithm = "SHA-256";

    public const int DigestLengthBytes = 32;

    public const int DigestHexLength = 64;

    public const string DomainSeparator =
        "I-MORTAL/USER-DEVICE-FINGERPRINT/SHA-256/V1";

    public const bool CanonicalSerializerInputRequired = true;

    public const bool CanonicalSerializerBypassForbidden = true;

    public const bool EmptyCanonicalInputForbidden = true;

    public const bool PublicIdentityMaterialOnly = true;

    public const bool PrivateKeyMaterialForbidden = true;

    public const bool HardwareBackedPrivateKeyRequired = true;

    public const bool NonExportablePrivateKeyRequired = true;

    public const bool PrivateKeyTransferForbidden = true;

    public const bool PrivateKeySynchronizationForbidden = true;

    public const bool FingerprintIsSecret = false;

    public const bool FingerprintIdentificationAndBindingOnly = true;

    public const bool FingerprintAloneCanAuthenticate = false;

    public const bool FreshAuthenticationChallengeRequired = true;

    public const bool HardwareKeyProofOfPossessionRequired = true;

    public const bool PerDeviceFingerprintRequired = true;

    public const bool IndependentDeviceIdentitiesRequired = true;

    public const bool MultipleDevicesPerAccountAllowed = true;

    public const bool CanReplaceDeveloperUsbIdentity = false;

    public const bool CanGrantSourceAccess = false;

    public const bool CanGrantSourceMutationAuthority = false;

    public const bool CanGrantDeveloperSigningAuthority = false;

    public const bool CanGrantProductionAuthority = false;

    public const bool CanGrantTeeAuthority = false;

    public const bool AttestedConfidentialIdentityPlaneRequired = true;

    public const bool FailOpenAllowed = false;

    public const bool DefaultDecisionDeny = true;
}