namespace IMortal.TrustBroker.Security.Sensors;

public enum AccountSecurityEventKind
{ AuthenticationFailed, AuthenticationSucceeded, AccountRecovery, CredentialChanged, MfaChanged, VerifiedEmailChanged }
public enum SessionSecurityEventKind
{ Created, Refreshed, PrivilegeChanged, Revoked, ConcurrentUseObserved }
public enum DeviceSecurityEventKind
{ EnrolledProofObserved, UnknownDevice, InvalidProof, ReplayedProof, RevokedEnrollment, EnrollmentChanged }

// These records are observations awaiting independent verification. No raw token,
// cookie, password, private key, email address or challenge secret belongs here.
public sealed record AccountSecurityObservation(string ProviderId, string ProtectedAccountReference,
    string EventId, long Sequence, AccountSecurityEventKind Kind, string ProtectedProvenanceReference);
public sealed record SessionSecurityObservation(string ProtectedSessionReference, string EventId,
    SessionSecurityEventKind Kind, string ProtectedProvenanceReference);
public sealed record DeviceSecurityObservation(string ProtectedEnrollmentReference, long EnrollmentVersion,
    string ProtectedProofReference, DeviceSecurityEventKind Kind, string ProtectedProvenanceReference);
public sealed record DestinationSecurityObservation(string ProtectedRegistryReference, long RegistryVersion,
    string Network, string Address, string ControlScope, string ProtectedControlEvidenceReference,
    string? WithdrawalId, string? ProviderBlockchainTransactionId);

/// <summary>Authenticate the live instance and loaded modules, not just a file path.</summary>
public sealed class RunningWorkloadObservation
{
    public RunningWorkloadObservation(string protectedInstanceReference, SignedSensorArtifact artifact,
        IEnumerable<SignedSensorArtifact> loadedModules, string protectedMeasurementReference)
    { ProtectedInstanceReference = protectedInstanceReference; Artifact = artifact;
      LoadedModules = Array.AsReadOnly(loadedModules.ToArray()); ProtectedMeasurementReference = protectedMeasurementReference; }
    public string ProtectedInstanceReference { get; }
    public SignedSensorArtifact Artifact { get; }
    public IReadOnlyList<SignedSensorArtifact> LoadedModules { get; }
    public string ProtectedMeasurementReference { get; }
}

/// <summary>
/// Each surface must have its own authenticated acquisition/verification pipeline.
/// None of these methods changes policy, issues authorization, or activates TEE.
/// Return null when unavailable; emit gap/rejection findings for observed failures.
/// </summary>
public interface IPlatformIntegrityTelemetry
{
    Task<SensorEvidence?> RunningWorkloadAsync(SensorEvaluationRequest request, SensorScope scope, SensorPolicy policy, CancellationToken cancellation);
    Task<SensorEvidence?> SecurityPolicyAsync(SensorEvaluationRequest request, SensorScope scope, SensorPolicy policy, CancellationToken cancellation);
    Task<SensorEvidence?> TeeMeasurementAsync(SensorEvaluationRequest request, SensorScope scope, SensorPolicy policy, CancellationToken cancellation);
    Task<SensorEvidence?> AttestationStateAsync(SensorEvaluationRequest request, SensorScope scope, SensorPolicy policy, CancellationToken cancellation);
    Task<SensorEvidence?> ProtectedStateAsync(SensorEvaluationRequest request, SensorScope scope, SensorPolicy policy, CancellationToken cancellation);
    Task<SensorEvidence?> SensorSelfIntegrityAsync(SensorEvaluationRequest request, SensorScope scope, SensorPolicy policy, CancellationToken cancellation);
}

/// <summary>Authenticated, least-privilege read-only feeds. Never execute trades or withdrawals.</summary>
public interface IUserAssetSecurityTelemetry
{
    Task<SensorEvidence?> AccountAuthenticationAsync(SensorScope scope, SensorPolicy policy, ProtectedUserRegistrySnapshot registry, CancellationToken cancellation);
    Task<SensorEvidence?> DevicePossessionAsync(SensorScope scope, SensorPolicy policy, ProtectedUserRegistrySnapshot registry, CancellationToken cancellation);
    Task<SensorEvidence?> SessionIntegrityAsync(SensorScope scope, SensorPolicy policy, ProtectedUserRegistrySnapshot registry, CancellationToken cancellation);
    Task<SensorEvidence?> TradingActivityAsync(SensorScope scope, SensorPolicy policy, ProtectedUserRegistrySnapshot registry, CancellationToken cancellation);
    Task<SensorEvidence?> UnauthorizedTransferAsync(SensorScope scope, SensorPolicy policy, ProtectedUserRegistrySnapshot registry, CancellationToken cancellation);
    Task<SensorEvidence?> WithdrawalDestinationAsync(SensorScope scope, SensorPolicy policy, ProtectedUserRegistrySnapshot registry, CancellationToken cancellation);
}
