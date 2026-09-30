using IMortal.TrustBroker.Security.ConfidentialCompute;

namespace IMortal.TrustBroker.Security.Sensors;

public enum SensorPlane { PlatformIntegrity, UserAssetSecurity }
public enum SensorHealth { NotEstablished, Unavailable, Degraded, Healthy }
public enum SensorVerificationState { NotEstablished, Unavailable, Rejected, Verified }
public enum SensorSurface
{
    SourceIntegrity, RunningWorkload, SecurityPolicy, TeeMeasurement, AttestationState,
    ProtectedState, SensorSelfIntegrity,
    AccountAuthentication, DevicePossession, SessionIntegrity, TradingActivity,
    UnauthorizedTransfer, WithdrawalDestination
}
public enum SensorCondition
{
    ConfirmedPolicyViolation, SuspiciousActivity, InsufficientEvidence,
    ContentAdded, ContentDeleted, ContentModified, ContentRenamed, InventoryScopeChanged,
    AuthorizedChangeObserved, AttemptedWriteObserved, MissedEvents, WatcherOverflow,
    InaccessibleSurface, ScanFailure, UnstableSnapshot, UnavailableVerifier,
    InvalidEvidence, HeartbeatLost, CollectionDisabled, ConfigurationChanged,
    AuditDeliveryFailure, NotificationNotEstablished
}

/// <summary>Claims to resolve, not authority. No credentials, tokens, keys or email addresses.</summary>
public sealed record SensorEvaluationRequest(Guid EvaluationId, string TenantClaim, string UserClaim,
    string Workload, DateTimeOffset EvaluationTime, RootEvaluationRequest? AuthorizationEvaluation = null);

/// <summary>Authenticated scope must come from an independent resolver, never copied blindly from claims.</summary>
public sealed record SensorScope(SensorEvaluationRequest Request, SensorPlane Plane,
    string TenantId, string UserId, string ScopeRevision);

/// <summary>Only codes and protected references may enter incident output; no raw event payloads.</summary>
public sealed record SensorFinding(SensorSurface Surface, SensorCondition Condition, string ProtectedEventReference);

/// <summary>Untrusted acquisition output until independently verified for the exact request and scope.</summary>
public sealed class SensorEvidence
{
    public SensorEvidence(SensorEvaluationRequest request, SensorScope scope, SensorSurface surface,
        DateTimeOffset observedAt, DateTimeOffset validUntil, string policyVersion,
        string provenanceReference, bool coverageComplete, IEnumerable<SensorFinding> findings)
    {
        Request = request; Scope = scope; Surface = surface; ObservedAt = observedAt; ValidUntil = validUntil;
        PolicyVersion = policyVersion; ProvenanceReference = provenanceReference; CoverageComplete = coverageComplete;
        Findings = Array.AsReadOnly(findings.ToArray());
    }
    public SensorEvaluationRequest Request { get; }
    public SensorScope Scope { get; }
    public SensorSurface Surface { get; }
    public DateTimeOffset ObservedAt { get; }
    public DateTimeOffset ValidUntil { get; }
    public string PolicyVersion { get; }
    public string ProvenanceReference { get; }
    public bool CoverageComplete { get; }
    public IReadOnlyList<SensorFinding> Findings { get; }
}

public sealed class SensorEvaluationResult
{
    internal SensorEvaluationResult(SensorPlane plane, SensorHealth health, IEnumerable<SensorFinding> findings,
        string? checkpoint = null, bool notificationQueued = false)
    { Plane = plane; Health = health; Findings = Array.AsReadOnly(findings.ToArray());
      AuditCheckpoint = checkpoint; NotificationQueued = notificationQueued; }
    public SensorPlane Plane { get; }
    public SensorHealth Health { get; }
    public IReadOnlyList<SensorFinding> Findings { get; }
    public string? AuditCheckpoint { get; }
    public bool NotificationQueued { get; }
    // Deliberately no authorization result, capability, signing or transfer operation.
}
