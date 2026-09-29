namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface ICryptographicContractEnvelopeVerifier
{
    bool Verify(
        CryptographicContractEnvelope envelope,
        TrustedProducerProvenance provenance,
        VeraCryptUsbKeyCustodyDescriptor custody);
}
