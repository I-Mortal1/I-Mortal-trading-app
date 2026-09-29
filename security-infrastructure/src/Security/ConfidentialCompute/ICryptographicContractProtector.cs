namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface ICryptographicContractProtector
{
    CryptographicContractEnvelope Encrypt(
        ContractEncryptionRequest request);

    bool VerifyEnvelope(
        CryptographicContractEnvelope envelope,
        VeraCryptUsbKeyCustodyDescriptor custody);

    byte[] Decrypt(
        ContractDecryptionRequest request,
        CryptographicContractEnvelope envelope);
}