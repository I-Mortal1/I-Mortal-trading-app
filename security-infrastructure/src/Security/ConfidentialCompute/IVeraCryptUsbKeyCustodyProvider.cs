namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IVeraCryptUsbKeyCustodyProvider
{
    VeraCryptUsbKeyCustodyDescriptor GetRequiredCustody(
        string keyIdentifier);
}
