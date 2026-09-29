namespace IMortal.TrustBroker.Security;

public enum SecurityEnrollmentState
{
    None = 0,
    RegistrationAccepted = 1,
    ProviderDetected = 2,
    HardwareReady = 3,
    IdentityEnrolled = 4,
    UserAuthorized = 5,
    ProductionAuthorized = 6,
    Revoked = 7
}
