using IMortal.TrustBroker.Providers;

namespace IMortal.TrustBroker.Security;

public sealed record UserSecurityProfile(
    string UserId,
    string SecurityInstanceId,
    string RegistrationNonceHash,
    string SecurityPolicyVersion,
    string SecurityPolicySha256,
    string ProviderId,
    TrustProviderState TrustState,
    bool HardwareBacked,
    bool NonExportableKeysSupported,
    SecurityEnrollmentState EnrollmentState,
    bool ProductionAuthorized);
