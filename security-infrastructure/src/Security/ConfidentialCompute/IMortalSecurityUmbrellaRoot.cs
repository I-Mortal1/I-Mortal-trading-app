using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// I-Mortal Security Umbrella root composition.
///
/// This is the common security owner above Windows, Linux, macOS,
/// Android, and iOS adapters.
///
/// Platform adapters provide evidence/capabilities only. They do not own
/// root authority.
///
/// IMPORTANT:
/// The current composition remains intentionally non-production-authorized.
/// </summary>
public sealed partial class IMortalSecurityUmbrellaRoot
{
    private readonly RootConfidentialComputeGate _confidentialComputeGate;
    private readonly IApprovedWorkloadGate _approvedWorkloadGate;
    private readonly IUserRuntimeSecurityGate _userRuntimeSecurityGate;
    private readonly IDeveloperSourceAuthorityGate _developerSourceAuthorityGate;

    private readonly ISecurityClock _securityClock;
    private readonly IApprovedWorkloadContextProducer _approvedWorkloadContextProducer;
    public IMortalSecurityUmbrellaRoot(
        RootConfidentialComputeGate confidentialComputeGate,
        IApprovedWorkloadGate approvedWorkloadGate,
        IUserRuntimeSecurityGate userRuntimeSecurityGate,
        IDeveloperSourceAuthorityGate developerSourceAuthorityGate,
        ISecurityClock securityClock)
        : this(confidentialComputeGate, approvedWorkloadGate, userRuntimeSecurityGate,
            developerSourceAuthorityGate, securityClock, null)
    {
    }

    public IMortalSecurityUmbrellaRoot(
        RootConfidentialComputeGate confidentialComputeGate,
        IApprovedWorkloadGate approvedWorkloadGate,
        IUserRuntimeSecurityGate userRuntimeSecurityGate,
        IDeveloperSourceAuthorityGate developerSourceAuthorityGate,
        ISecurityClock securityClock,
        IApprovedWorkloadContextProducer? approvedWorkloadContextProducer)
    {
        _confidentialComputeGate =
            confidentialComputeGate ??
            throw new ArgumentNullException(
        nameof(confidentialComputeGate)
    );

        _approvedWorkloadGate =
            approvedWorkloadGate ??
            throw new ArgumentNullException(nameof(approvedWorkloadGate));

        _userRuntimeSecurityGate =
            userRuntimeSecurityGate ??
            throw new ArgumentNullException(nameof(userRuntimeSecurityGate));

        _developerSourceAuthorityGate =
            developerSourceAuthorityGate ??
            throw new ArgumentNullException(nameof(developerSourceAuthorityGate));
        _securityClock = securityClock ?? throw new ArgumentNullException(nameof(securityClock));
        _approvedWorkloadContextProducer = approvedWorkloadContextProducer ??
            new DenyAllApprovedWorkloadContextProducer();
    }

    /// <summary>
    /// Evaluate the complete root composition.
    ///
    /// productionAuthorized must originate from the separately protected
    /// production policy. This method does not manufacture that state.
    /// </summary>
    public UmbrellaRootAuthorizationResult Evaluate(
        UmbrellaSecurityDomain domain,
        bool productionAuthorized,
        DeveloperSourceAuthorityMode developerAuthorityMode =
            DeveloperSourceAuthorityMode.None
    )
    {
        // Legacy callers lack operation, identity version and authoritative lifecycle.
        // Retain the signature but never manufacture those prerequisites.
        return Deny(productionAuthorized
            ? UmbrellaRootDenialReason.SecurityDependencyFailure
            : UmbrellaRootDenialReason.ProductionDisabled);
    }

    private static UmbrellaRootAuthorizationResult Deny(
        UmbrellaRootDenialReason reason)
        => UmbrellaRootAuthorizationResult.Denied(reason);
}