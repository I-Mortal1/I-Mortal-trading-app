namespace IMortal.TrustBroker.Providers;

[Flags]
public enum TrustProviderCapabilities
{
    None = 0,
    Detection = 1,
    Enrollment = 2,
    Authorization = 4,
    Attestation = 8,
    Signing = 16,
    Revocation = 32
}
