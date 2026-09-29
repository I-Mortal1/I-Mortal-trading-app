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
public sealed class IMortalSecurityUmbrellaRoot
{
    private readonly RootConfidentialComputeGate _confidentialComputeGate;
    private readonly IApprovedWorkloadGate _approvedWorkloadGate;
    private readonly IUserRuntimeSecurityGate _userRuntimeSecurityGate;
    private readonly IDeveloperSourceAuthorityGate _developerSourceAuthorityGate;

    public IMortalSecurityUmbrellaRoot(
        RootConfidentialComputeGate confidentialComputeGate,
        IApprovedWorkloadGate approvedWorkloadGate,
        IUserRuntimeSecurityGate userRuntimeSecurityGate,
        IDeveloperSourceAuthorityGate developerSourceAuthorityGate)
    {
        _confidentialComputeGate =
            confidentialComputeGate ??
            throw new ArgumentNullException(nameof(confidentialComputeGate));

        _approvedWorkloadGate =
            approvedWorkloadGate ??
            throw new ArgumentNullException(nameof(approvedWorkloadGate));

        _userRuntimeSecurityGate =
            userRuntimeSecurityGate ??
            throw new ArgumentNullException(nameof(userRuntimeSecurityGate));

        _developerSourceAuthorityGate =
            developerSourceAuthorityGate ??
            throw new ArgumentNullException(nameof(developerSourceAuthorityGate));
    }

    /// <summary>
    /// Evaluate the complete root composition.
    ///
    /// productionAuthorized must originate from the separately protected
    /// production policy. This method does not manufacture that state.
    /// </summary>
    public UmbrellaRootAuthorizationResult Evaluate(
        UmbrellaSecurityDomain domain,
        DateTimeOffset now,
        bool productionAuthorized,
        DeveloperSourceAuthorityMode developerAuthorityMode =
            DeveloperSourceAuthorityMode.None)
    {
        // Absolute production kill switch.
        if (!productionAuthorized)
        {
            return Deny(
                UmbrellaRootDenialReason.ProductionDisabled);
        }

        if (domain is not
            (UmbrellaSecurityDomain.UserRuntime or
             UmbrellaSecurityDomain.DeveloperSourceCustody))
        {
            return Deny(
                UmbrellaRootDenialReason.InvalidSecurityDomain);
        }

        RootConfidentialComputeGateResult rootResult;

        try
        {
            rootResult =
                _confidentialComputeGate.Evaluate(
                    now,
                    productionContext: true);
        }
        catch
        {
            return Deny(
                UmbrellaRootDenialReason.SecurityDependencyFailure);
        }

        if (rootResult.State != RootConfidentialComputeState.Satisfied)
        {
            return Deny(
                UmbrellaRootDenialReason.RootConfidentialComputeGateDenied);
        }

        bool approvedWorkload;

        try
        {
            approvedWorkload =
                _approvedWorkloadGate.IsApproved();
        }
        catch
        {
            return Deny(
                UmbrellaRootDenialReason.SecurityDependencyFailure);
        }

        if (!approvedWorkload)
        {
            return Deny(
                UmbrellaRootDenialReason.ApprovedWorkloadDenied);
        }

        switch (domain)
        {
            case UmbrellaSecurityDomain.UserRuntime:
            {
                // Finished-app users never enter the developer source
                // authority branch.
                if (developerAuthorityMode !=
                    DeveloperSourceAuthorityMode.None)
                {
                    return Deny(
                        UmbrellaRootDenialReason
                            .UserRuntimeSourceAuthorityForbidden);
                }

                bool userRuntimeSatisfied;

                try
                {
                    userRuntimeSatisfied =
                        _userRuntimeSecurityGate.IsSatisfied();
                }
                catch
                {
                    return Deny(
                        UmbrellaRootDenialReason.SecurityDependencyFailure);
                }

                if (!userRuntimeSatisfied)
                {
                    return Deny(
                        UmbrellaRootDenialReason.SecurityDependencyFailure);
                }

                return UmbrellaRootAuthorizationResult.Satisfied();
            }

            case UmbrellaSecurityDomain.DeveloperSourceCustody:
            {
                if (developerAuthorityMode is not
                    (DeveloperSourceAuthorityMode.NormalUsb or
                     DeveloperSourceAuthorityMode.UsbUnavailableEmailRecovery))
                {
                    return Deny(
                        UmbrellaRootDenialReason
                            .UnsupportedDeveloperAuthorityMode);
                }

                bool developerAuthoritySatisfied;

                try
                {
                    developerAuthoritySatisfied =
                        _developerSourceAuthorityGate.IsSatisfied(
                            developerAuthorityMode);
                }
                catch
                {
                    return Deny(
                        UmbrellaRootDenialReason.SecurityDependencyFailure);
                }

                if (!developerAuthoritySatisfied)
                {
                    return Deny(
                        UmbrellaRootDenialReason.DeveloperAuthorityDenied);
                }

                return UmbrellaRootAuthorizationResult.Satisfied();
            }

            default:
                return Deny(
                    UmbrellaRootDenialReason.InvalidSecurityDomain);
        }
    }

    private static UmbrellaRootAuthorizationResult Deny(
        UmbrellaRootDenialReason reason)
        => UmbrellaRootAuthorizationResult.Denied(reason);
}