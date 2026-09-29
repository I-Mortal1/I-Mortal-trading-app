namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable policy describing the future encrypted project-signing-key
/// security boundary.
///
/// This policy does not unlock VeraCrypt, access USB storage, generate keys,
/// decrypt keys, sign data, or grant authority.
///
/// Production key use requires the conjunction of the independent security
/// gates represented here.
/// </summary>
public sealed class EncryptedProjectSigningKeyPolicy
{
    private EncryptedProjectSigningKeyPolicy()
    {
    }

    public static EncryptedProjectSigningKeyPolicy Required { get; } =
        new();

    public bool RequirePlatformAttestation => true;

    public bool RequireMeasurementPolicyAcceptance => true;

    public bool RequireRootConfidentialComputeGate => true;

    public bool RequireAuthorizedUserAuthentication => true;

    public bool RequireAuthorizedVeraCryptUsb => true;

    public bool RequireEncryptedSigningKey => true;

    public bool RequireSignedScopedCapability => true;

    public bool RequireProjectAccessPolicy => true;

    public bool AllowPlaintextKeyPersistence => false;

    public bool AllowUnencryptedKeyStorage => false;

    public bool AllowKeyExportToOrdinaryHost => false;

    public bool AllowKeyExportToAi => false;

    public bool AllowKeyExportToExternalApplication => false;

    public bool AllowUsbPossessionAsStandaloneAuthority => false;

    public bool AllowVeraCryptPasswordAsStandaloneAuthority => false;

    public bool AllowSigningKeyPossessionAsStandaloneAuthority => false;

    public bool AllowAttestationAsStandaloneProjectAuthority => false;

    public bool AllowVeraCryptToBypassAttestation => false;

    public bool AllowAttestationToBypassVeraCrypt => false;

    public bool AllowFailOpen => false;
}
