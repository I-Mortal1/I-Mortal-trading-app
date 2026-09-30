namespace IMortal.TrustBroker.Security.Sensors;

public interface ISensorScopeResolver
{
    Task<SensorScope?> ResolveAsync(SensorEvaluationRequest request, SensorPlane plane, CancellationToken cancellation);
}
public interface ISensorEvidenceSource
{
    // Read-only acquisition only. Provider/tenant/account binding, event id/sequence,
    // reconciliation gaps and observed surface must be covered by provenance.
    Task<SensorEvidence?> CollectAsync(SensorEvaluationRequest request, SensorScope scope,
        SensorSurface surface, SensorPolicy policy, ProtectedUserRegistrySnapshot? registry, CancellationToken cancellation);
}
public interface ISensorEvidenceVerifier
{
    // Verify origin, signatures, scope, policy and surface semantics independently.
    // TEE/attestation adapters must authenticate the exact root evaluation, shared
    // authoritative challenge, workload and consumed/valid replay record; they do not
    // issue/consume new authorization challenges or infer trust from sensor output.
    Task<SensorVerificationState> VerifyAsync(SensorEvidence evidence, SensorPolicy policy,
        ProtectedUserRegistrySnapshot? registry, CancellationToken cancellation);
}
public sealed record SensorProbe(ISensorEvidenceSource Source, ISensorEvidenceVerifier Verifier);

public sealed class SensorDependencies
{
    public SensorDependencies(ISensorScopeResolver? scopes = null, ISensorPolicyVerifier? policies = null,
        IIndependentSensorMonitor? monitor = null, IIncidentLedger? ledger = null,
        IReadOnlyDictionary<SensorSurface, SensorProbe>? probes = null,
        IProtectedUserRegistry? registry = null, INotificationEnrollmentVerifier? notifications = null,
        ISecurityNotificationOutbox? outbox = null)
    {
        Scopes = scopes; Policies = policies; Monitor = monitor; Ledger = ledger;
        Probes = new System.Collections.ObjectModel.ReadOnlyDictionary<SensorSurface, SensorProbe>(
            probes is null ? new Dictionary<SensorSurface, SensorProbe>() : new Dictionary<SensorSurface, SensorProbe>(probes));
        Registry = registry; Notifications = notifications; Outbox = outbox;
    }
    internal ISensorScopeResolver? Scopes { get; }
    internal ISensorPolicyVerifier? Policies { get; }
    internal IIndependentSensorMonitor? Monitor { get; }
    internal IIncidentLedger? Ledger { get; }
    internal IReadOnlyDictionary<SensorSurface, SensorProbe> Probes { get; }
    internal IProtectedUserRegistry? Registry { get; }
    internal INotificationEnrollmentVerifier? Notifications { get; }
    internal ISecurityNotificationOutbox? Outbox { get; }
}

/// <summary>Explicit adapter for an unsupported infrastructure surface.</summary>
public sealed class UnavailableSensorAdapter : ISensorEvidenceSource, ISensorEvidenceVerifier
{
    public Task<SensorEvidence?> CollectAsync(SensorEvaluationRequest request, SensorScope scope,
        SensorSurface surface, SensorPolicy policy, ProtectedUserRegistrySnapshot? registry, CancellationToken cancellation) => Task.FromResult<SensorEvidence?>(null);
    public Task<SensorVerificationState> VerifyAsync(SensorEvidence evidence, SensorPolicy policy,
        ProtectedUserRegistrySnapshot? registry, CancellationToken cancellation) => Task.FromResult(SensorVerificationState.Unavailable);
}
