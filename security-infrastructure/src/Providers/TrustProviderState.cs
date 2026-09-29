namespace IMortal.TrustBroker.Providers;

public enum TrustProviderState
{
    Unavailable = 0,
    ProviderAvailable = 1,
    HardwareDetected = 2,
    HardwareReady = 3,
    IdentityEnrolled = 4,
    UserAuthorized = 5,
    ProductionAuthorized = 6
}
