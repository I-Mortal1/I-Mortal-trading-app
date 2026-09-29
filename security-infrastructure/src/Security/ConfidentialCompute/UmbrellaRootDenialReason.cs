namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public enum UmbrellaRootDenialReason
{
    None = 0,

    ProductionDisabled,
    InvalidSecurityDomain,
    RootConfidentialComputeGateMissing,
    RootConfidentialComputeGateDenied,
    ApprovedWorkloadGateMissing,
    ApprovedWorkloadDenied,
    UserRuntimeSourceAuthorityForbidden,
    DeveloperAuthorityGateMissing,
    DeveloperAuthorityDenied,
    UnsupportedDeveloperAuthorityMode,
    SecurityDependencyFailure
}