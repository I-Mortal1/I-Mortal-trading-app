namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed partial class IMortalSecurityUmbrellaRoot
{
    private readonly AuthorizationFoundation? _foundation;

    public IMortalSecurityUmbrellaRoot(RootConfidentialComputeGate confidentialComputeGate,
        IApprovedWorkloadGate approvedWorkloadGate, IUserRuntimeSecurityGate userRuntimeSecurityGate,
        IDeveloperSourceAuthorityGate developerSourceAuthorityGate, ISecurityClock securityClock,
        IApprovedWorkloadContextProducer? approvedWorkloadContextProducer, AuthorizationFoundation foundation)
        : this(confidentialComputeGate, approvedWorkloadGate, userRuntimeSecurityGate,
            developerSourceAuthorityGate, securityClock, approvedWorkloadContextProducer)
    { _foundation = foundation ?? throw new ArgumentNullException(nameof(foundation)); }

    /// <summary>
    /// One evaluation and one authoritative lifecycle. productionAuthorized must still
    /// originate in protected composition. No success is cached or stored on the root.
    /// The result is scoped to this intent; it is not a reusable execution capability.
    /// </summary>
    public UmbrellaRootAuthorizationResult Evaluate(AuthorizationIntent intent, bool productionAuthorized)
    {
        if (!productionAuthorized) return Deny(UmbrellaRootDenialReason.ProductionDisabled);
        try
        {
            if (!ValidIntent(intent) || _foundation is null ||
                _foundation.TeeProvider is null || _foundation.TeeVerifier is null)
                return Deny(UmbrellaRootDenialReason.SecurityDependencyFailure);
            var time = _securityClock.UtcNow;
            if (time == default) return Deny(UmbrellaRootDenialReason.SecurityDependencyFailure);
            var request = new RootEvaluationRequest(intent, time);
            var lifecycle = _foundation.Lifecycle;
            if (!lifecycle.TryIssue(request, out var issued) || issued is null ||
                !ReferenceEquals(issued.Owner, request) || !ValidIssuance(issued) || !lifecycle.IsCurrent(issued))
                return Deny(UmbrellaRootDenialReason.SecurityDependencyFailure);

            if (!_confidentialComputeGate.Evaluate(issued, _foundation.TeeProvider, _foundation.TeeVerifier).IsSatisfied)
                return Deny(UmbrellaRootDenialReason.RootConfidentialComputeGateDenied);

            var workloadRequest = new ApprovedWorkloadEvaluationRequest(issued);
            if (!_approvedWorkloadContextProducer.TryProduce(workloadRequest, out var workload) ||
                workload is null || !workload.BelongsTo(workloadRequest) || workload.EvaluationTime != time ||
                !ReferenceEquals(workload.Challenge, issued.Challenge) ||
                !ReferenceEquals(workload.RequiredPolicy, issued.RequiredPolicy) ||
                !_approvedWorkloadGate.IsApproved(workload))
                return Deny(UmbrellaRootDenialReason.ApprovedWorkloadDenied);

            DeveloperAuthorityContext? developer = null;
            if (intent.Domain == UmbrellaSecurityDomain.DeveloperSourceCustody)
            {
                if (!lifecycle.TryBeginProofAttempt(issued))
                    return Deny(UmbrellaRootDenialReason.DeveloperAuthorityDenied);
                var developerRequest = new DeveloperAuthorityRequest(issued);
                if (_foundation.DeveloperProducer?.TryProduce(developerRequest, out developer) != true ||
                    developer is null || !developer.BelongsTo(developerRequest) ||
                    !DeveloperAuthorityBindings.Match(developer) || !_developerSourceAuthorityGate.IsSatisfied(developer))
                    return Deny(UmbrellaRootDenialReason.DeveloperAuthorityDenied);
            }
            else if (!_userRuntimeSecurityGate.IsSatisfied())
                return Deny(UmbrellaRootDenialReason.SecurityDependencyFailure);

            // The authority rechecks trusted current time and all authoritative state
            // under its durable single-use commit boundary, including USB availability.
            // Failure/ambiguity denies. Never approve before commit and never retry it.
            if (!lifecycle.TryCommit(new AuthorizationCommit(issued, developer)))
                return Deny(UmbrellaRootDenialReason.SecurityDependencyFailure);
            return UmbrellaRootAuthorizationResult.Satisfied();
        }
        catch { return Deny(UmbrellaRootDenialReason.SecurityDependencyFailure); }
    }

    private static bool ValidIntent(AuthorizationIntent? i) => i is not null &&
        !string.IsNullOrWhiteSpace(i.Operation) && !string.IsNullOrWhiteSpace(i.Workload) &&
        i.Platform is ConfidentialPlatformClass.IntelTdx or ConfidentialPlatformClass.AmdSevSnp &&
        (i.Domain == UmbrellaSecurityDomain.UserRuntime
            ? i.DeveloperMode == DeveloperSourceAuthorityMode.None && i.IdentityVersion == 0 && i.DeveloperIdentity == ""
            : i.Domain == UmbrellaSecurityDomain.DeveloperSourceCustody && i.IdentityVersion > 0 &&
              !string.IsNullOrWhiteSpace(i.DeveloperIdentity) &&
              i.DeveloperMode is DeveloperSourceAuthorityMode.NormalUsb or DeveloperSourceAuthorityMode.UsbUnavailableEmailRecovery);

    private static bool ValidIssuance(IssuedAuthorization issued)
    {
        var c = issued.Challenge; var r = issued.Owner;
        return c.Nonce.Length >= 32 && c.IssuedAt != default && c.IssuedAt <= r.EvaluationTime &&
            c.ExpiresAt > r.EvaluationTime && c.ExpiresAt > c.IssuedAt &&
            c.ExpectedPlatform == r.Intent.Platform && string.Equals(c.WorkloadBinding, r.Intent.Workload, StringComparison.Ordinal) &&
            (r.Intent.Domain == UmbrellaSecurityDomain.UserRuntime
                ? issued.DeveloperIdentity is null
                : issued.DeveloperIdentity?.IdentityVersion == r.Intent.IdentityVersion);
    }
}
