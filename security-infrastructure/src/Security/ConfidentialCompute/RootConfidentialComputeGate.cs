namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class RootConfidentialComputeGate
{
    /// <summary>Shared transaction path; never falls back to parameterless acquisition.</summary>
    public RootConfidentialComputeGateResult Evaluate(IssuedAuthorization issued,
        ITransactionTeeEvidenceProvider provider, ITransactionTeeVerifier verifier)
    {
        try
        {
            var raw = provider.Collect(issued);
            if (raw is null) return Deny(RootConfidentialComputeDenialReason.NoEvidence);
            // Read each asserted field once, then verify the immutable snapshot. This
            // snapshot is NOT trusted merely because its type is named Verified.
            var snapshot = new VerifiedConfidentialComputeEvidence(raw.Origin, raw.PlatformClass,
                raw.TeeBoundaryPresent, raw.RemoteAttestationPresent, raw.AttestationIssuedAt,
                raw.AttestationExpiresAt, raw.Measurement, raw.MeasurementPolicyId,
                raw.WorkloadIdentity, raw.PlatformIdentity, raw.SecurityPolicyId, raw.SignedArtifactDigest);
            var normalized = VerifiedEvidenceNormalizer.NormalizeVerified(snapshot, issued.Owner.EvaluationTime);
            if (!normalized.Succeeded || snapshot.PlatformClass != issued.Challenge.ExpectedPlatform ||
                snapshot.WorkloadIdentity != issued.Challenge.WorkloadBinding ||
                snapshot.AttestationIssuedAt < issued.Challenge.IssuedAt ||
                !verifier.Verify(issued, snapshot) || !_attestationVerifier.Verify(snapshot) ||
                !_measurementPolicy.Accept(snapshot))
                return Deny(RootConfidentialComputeDenialReason.AttestationInvalid);
            return new(RootConfidentialComputeState.Satisfied, RootConfidentialComputeDenialReason.None,
                snapshot.PlatformClass, snapshot.AttestationExpiresAt);
        }
        catch { return Deny(RootConfidentialComputeDenialReason.VerifierFailure); }
    }

    private readonly IConfidentialComputeEvidenceProvider _evidenceProvider;
    private readonly IConfidentialComputeAttestationVerifier _attestationVerifier;
    private readonly IConfidentialComputeMeasurementPolicy _measurementPolicy;

    public RootConfidentialComputeGate(
        IConfidentialComputeEvidenceProvider evidenceProvider,
        IConfidentialComputeAttestationVerifier attestationVerifier,
        IConfidentialComputeMeasurementPolicy measurementPolicy)
    {
        _evidenceProvider =
            evidenceProvider ?? throw new ArgumentNullException(nameof(evidenceProvider));

        _attestationVerifier =
            attestationVerifier ?? throw new ArgumentNullException(nameof(attestationVerifier));

        _measurementPolicy =
            measurementPolicy ?? throw new ArgumentNullException(nameof(measurementPolicy));
    }

    public RootConfidentialComputeGateResult Evaluate(
        DateTimeOffset now,
        bool productionContext = true)
    {
        IConfidentialComputeEvidence? evidence;

        try
        {
            evidence = _evidenceProvider.Collect();
        }
        catch
        {
            return Deny(
                RootConfidentialComputeDenialReason.EvidenceProviderFailure);
        }

        if (evidence is null)
            return Deny(RootConfidentialComputeDenialReason.NoEvidence);

        if (evidence.Origin == ConfidentialEvidenceOrigin.Unknown)
            return Deny(
                RootConfidentialComputeDenialReason.UnknownEvidenceOrigin,
                evidence.PlatformClass);

        if (productionContext &&
            evidence.Origin != ConfidentialEvidenceOrigin.Production)
        {
            return Deny(
                RootConfidentialComputeDenialReason.TestEvidenceInProduction,
                evidence.PlatformClass);
        }

        if (evidence.PlatformClass is not
            (ConfidentialPlatformClass.IntelTdx or
             ConfidentialPlatformClass.AmdSevSnp))
        {
            return Deny(
                RootConfidentialComputeDenialReason.UnsupportedPlatform,
                evidence.PlatformClass);
        }

        if (!evidence.TeeBoundaryPresent)
        {
            return Deny(
                RootConfidentialComputeDenialReason.TeeBoundaryMissing,
                evidence.PlatformClass);
        }

        if (!evidence.RemoteAttestationPresent)
        {
            return Deny(
                RootConfidentialComputeDenialReason.AttestationMissing,
                evidence.PlatformClass);
        }

        if (evidence.AttestationIssuedAt > now ||
            evidence.AttestationExpiresAt <= now)
        {
            return Deny(
                RootConfidentialComputeDenialReason.AttestationStale,
                evidence.PlatformClass);
        }

        bool attestationValid;

        try
        {
            attestationValid = _attestationVerifier.Verify(evidence);
        }
        catch
        {
            return Deny(
                RootConfidentialComputeDenialReason.VerifierFailure,
                evidence.PlatformClass);
        }

        if (!attestationValid)
        {
            return Deny(
                RootConfidentialComputeDenialReason.AttestationInvalid,
                evidence.PlatformClass);
        }

        bool policyAccepted;

        try
        {
            policyAccepted = _measurementPolicy.Accept(evidence);
        }
        catch
        {
            return Deny(
                RootConfidentialComputeDenialReason.PolicyFailure,
                evidence.PlatformClass);
        }

        if (!policyAccepted)
        {
            return Deny(
                RootConfidentialComputeDenialReason.MeasurementInvalid,
                evidence.PlatformClass);
        }

        return new RootConfidentialComputeGateResult(
            RootConfidentialComputeState.Satisfied,
            RootConfidentialComputeDenialReason.None,
            evidence.PlatformClass,
            evidence.AttestationExpiresAt);
    }

    private static RootConfidentialComputeGateResult Deny(
        RootConfidentialComputeDenialReason reason,
        ConfidentialPlatformClass platform =
            ConfidentialPlatformClass.None)
    {
        return new RootConfidentialComputeGateResult(
            RootConfidentialComputeState.Denied,
            reason,
            platform,
            null);
    }
}
