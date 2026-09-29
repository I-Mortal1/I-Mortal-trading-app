namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IVeraCryptUsbCustodyOperations
{
    VeraCryptUsbKeyCustodyDescriptor GetRequiredCustody(
        string custodyIdentifier);

    bool IsRequiredCustodyAvailable(
        VeraCryptUsbKeyCustodyDescriptor custody);

    bool CanRead(
        VeraCryptUsbKeyCustodyDescriptor custody);

    bool CanWrite(
        VeraCryptUsbKeyCustodyDescriptor custody);

    bool CanModify(
        VeraCryptUsbKeyCustodyDescriptor custody);
}