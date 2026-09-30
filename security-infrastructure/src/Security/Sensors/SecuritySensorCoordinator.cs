using IMortal.TrustBroker.Security.Provisioning;

namespace IMortal.TrustBroker.Security.Sensors;

/// <summary>Reporting only. No reference to an authorization result or approving producer.</summary>
public sealed class SecuritySensorCoordinator
{
    public Task<SensorEvaluationResult> EvaluatePlatformIntegrityAsync(SensorEvaluationRequest request,
        DateTimeOffset capturedEvaluationTime, SensorPolicy policy, SignedSensorArtifact artifact,
        SensorDependencies dependencies, CancellationToken cancellation) =>
        EvaluateAsync(SensorPlane.PlatformIntegrity, request, capturedEvaluationTime, policy, artifact, dependencies, cancellation);

    public Task<SensorEvaluationResult> EvaluateUserAssetSecurityAsync(SensorEvaluationRequest request,
        DateTimeOffset capturedEvaluationTime, SensorPolicy policy, SignedSensorArtifact artifact,
        SensorDependencies dependencies, CancellationToken cancellation) =>
        EvaluateAsync(SensorPlane.UserAssetSecurity, request, capturedEvaluationTime, policy, artifact, dependencies, cancellation);

    private static async Task<SensorEvaluationResult> EvaluateAsync(SensorPlane plane, SensorEvaluationRequest request,
        DateTimeOffset time, SensorPolicy policy, SignedSensorArtifact artifact, SensorDependencies d, CancellationToken ct)
    {
        var findings = new List<SensorFinding>();
        SensorEvaluationResult Result(SensorHealth h, string? checkpoint = null, bool queued = false) => new(plane, h, findings, checkpoint, queued);
        void Gap(SensorSurface s, SensorCondition c) => findings.Add(new(s, c, ""));
        ct.ThrowIfCancellationRequested();
        try
        {
            if (request is null || request.EvaluationId == Guid.Empty || time == default || request.EvaluationTime != time ||
                string.IsNullOrWhiteSpace(request.Workload) || policy is null || artifact is null || d is null ||
                d.Scopes is null || d.Policies is null || d.Monitor is null || d.Ledger is null)
                return Result(SensorHealth.NotEstablished);
            if (request.AuthorizationEvaluation is { } root &&
                (root.EvaluationTime != time || root.Intent.Workload != request.Workload))
                return Result(SensorHealth.NotEstablished);
            var scope = await d.Scopes.ResolveAsync(request, plane, ct);
            if (scope is null || !ReferenceEquals(scope.Request, request) || scope.Plane != plane ||
                string.IsNullOrWhiteSpace(scope.TenantId) || string.IsNullOrWhiteSpace(scope.ScopeRevision) ||
                (plane == SensorPlane.UserAssetSecurity && string.IsNullOrWhiteSpace(scope.UserId)) ||
                !await d.Policies.VerifyAsync(scope, policy, ct) || !await d.Monitor.VerifyAsync(scope, policy, artifact, null, ct))
                return Result(SensorHealth.NotEstablished);

            ProtectedUserRegistrySnapshot? registry = null;
            if (plane == SensorPlane.UserAssetSecurity)
            {
                registry = d.Registry is null ? null : await d.Registry.ReadAsync(scope, ct);
                if (registry is null || !ReferenceEquals(registry.Scope, scope) || registry.Version <= 0 ||
                    string.IsNullOrWhiteSpace(registry.ProvenanceReference) || string.IsNullOrWhiteSpace(registry.VerifiedNotificationEmailReference) ||
                    !await d.Registry!.VerifyCurrentAsync(registry, ct)) return Result(SensorHealth.NotEstablished);
            }
            var surfaces = plane == SensorPlane.PlatformIntegrity
                ? new[] { SensorSurface.SourceIntegrity, SensorSurface.RunningWorkload, SensorSurface.SecurityPolicy,
                    SensorSurface.TeeMeasurement, SensorSurface.AttestationState, SensorSurface.ProtectedState, SensorSurface.SensorSelfIntegrity }
                : new[] { SensorSurface.AccountAuthentication, SensorSurface.DevicePossession, SensorSurface.SessionIntegrity,
                    SensorSurface.TradingActivity, SensorSurface.UnauthorizedTransfer, SensorSurface.WithdrawalDestination };
            int verified = 0;
            foreach (var surface in surfaces)
            {
                ct.ThrowIfCancellationRequested();
                if ((surface is SensorSurface.TeeMeasurement or SensorSurface.AttestationState) && request.AuthorizationEvaluation is null)
                { Gap(surface, SensorCondition.InsufficientEvidence); continue; }
                if (!d.Probes.TryGetValue(surface, out var probe) || probe.Source is null || probe.Verifier is null)
                { Gap(surface, SensorCondition.UnavailableVerifier); continue; }
                try
                {
                    var e = await probe.Source.CollectAsync(request, scope, surface, policy, registry, ct);
                    if (e is null) { Gap(surface, SensorCondition.InaccessibleSurface); continue; }
                    if (!ReferenceEquals(e.Request, request) || !ReferenceEquals(e.Scope, scope) || e.Surface != surface ||
                        e.PolicyVersion != policy.Version || string.IsNullOrWhiteSpace(e.ProvenanceReference) ||
                        e.ObservedAt == default || e.ObservedAt > time || time - e.ObservedAt > policy.MaximumEvidenceAge || e.ValidUntil <= time ||
                        e.Findings.Any(f => f is null || f.Surface != surface || !Enum.IsDefined(f.Condition) || (f.ProtectedEventReference != "" && !ProtectedOutputReference.IsValid(f.ProtectedEventReference))))
                    { Gap(surface, SensorCondition.InvalidEvidence); continue; }
                    var state = await probe.Verifier.VerifyAsync(e, policy, registry, ct);
                    if (state != SensorVerificationState.Verified)
                    { Gap(surface, state == SensorVerificationState.Rejected ? SensorCondition.InvalidEvidence : SensorCondition.UnavailableVerifier); continue; }
                    verified++;
                    findings.AddRange(e.Findings);
                    if (!e.CoverageComplete) Gap(surface, SensorCondition.MissedEvents);
                }
                catch (OperationCanceledException) { throw; }
                catch { Gap(surface, SensorCondition.ScanFailure); }
            }
            ct.ThrowIfCancellationRequested();
            // Recheck registry version before recording a conclusion; external atomic
            // checkpoints still own consistency across independent infrastructure.
            if (registry is not null && !await d.Registry!.VerifyCurrentAsync(registry, ct))
            { Gap(SensorSurface.WithdrawalDestination, SensorCondition.InvalidEvidence); return Result(SensorHealth.Degraded); }
            var findingsDigest = IncidentDigest.Compute(findings.AsReadOnly());
            var checkpoint = await d.Ledger.AppendAsync(scope, policy, findings.AsReadOnly(), ct);
            if (checkpoint is null || checkpoint.EvaluationId != request.EvaluationId || checkpoint.TenantId != scope.TenantId ||
                checkpoint.UserId != scope.UserId || checkpoint.Plane != plane || checkpoint.PolicyVersion != policy.Version || checkpoint.FindingsDigest != findingsDigest ||
                !ProtectedOutputReference.IsValid(checkpoint.ProtectedCheckpointReference) ||
                !await d.Monitor.VerifyAsync(scope, policy, artifact, checkpoint, ct))
            { Gap(SensorSurface.SensorSelfIntegrity, SensorCondition.AuditDeliveryFailure); return Result(SensorHealth.Degraded); }
            bool queued = false;
            if (findings.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                var enrollment = d.Notifications is null ? null : await d.Notifications.ResolveAsync(scope,
                    plane == SensorPlane.PlatformIntegrity ? NotificationPurpose.DeveloperSecurityReport : NotificationPurpose.UserSecurityReport, registry, ct);
                if (enrollment is not null && ReferenceEquals(enrollment.Scope, scope) &&
                    long.TryParse(enrollment.Version, out var enrollmentVersion) && enrollmentVersion > 0 && ProtectedOutputReference.IsValid(enrollment.ProtectedDestinationReference) && d.Outbox is not null)
                    queued = await d.Outbox.EnqueueAsync(enrollment, checkpoint, ct);
                if (!queued)
                {
                    Gap(SensorSurface.SensorSelfIntegrity, SensorCondition.NotificationNotEstablished);
                    if (!await d.Ledger.RecordNotificationFailureAsync(checkpoint, ct))
                        Gap(SensorSurface.SensorSelfIntegrity, SensorCondition.AuditDeliveryFailure);
                }
            }
            return Result(verified == surfaces.Length && findings.Count == 0 ? SensorHealth.Healthy :
                verified == 0 ? SensorHealth.Unavailable : SensorHealth.Degraded, checkpoint.ProtectedCheckpointReference, queued);
        }
        catch (OperationCanceledException) { throw; }
        catch
        { Gap(SensorSurface.SensorSelfIntegrity, SensorCondition.ScanFailure); return Result(SensorHealth.Degraded); }
    }
}
