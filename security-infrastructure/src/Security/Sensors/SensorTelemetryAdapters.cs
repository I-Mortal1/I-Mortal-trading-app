namespace IMortal.TrustBroker.Security.Sensors;

/// <summary>Read-only routing; independent ISensorEvidenceVerifier remains mandatory.</summary>
public sealed class PlatformIntegrityTelemetryAdapter(IPlatformIntegrityTelemetry? telemetry = null) : ISensorEvidenceSource
{
    public Task<SensorEvidence?> CollectAsync(SensorEvaluationRequest r, SensorScope s, SensorSurface surface,
        SensorPolicy p, ProtectedUserRegistrySnapshot? registry, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (telemetry is null || s.Plane != SensorPlane.PlatformIntegrity || !ReferenceEquals(s.Request, r) || registry is not null)
            return Task.FromResult<SensorEvidence?>(null);
        return surface switch {
            SensorSurface.RunningWorkload => telemetry.RunningWorkloadAsync(r,s,p,ct),
            SensorSurface.SecurityPolicy => telemetry.SecurityPolicyAsync(r,s,p,ct),
            SensorSurface.TeeMeasurement => telemetry.TeeMeasurementAsync(r,s,p,ct),
            SensorSurface.AttestationState => telemetry.AttestationStateAsync(r,s,p,ct),
            SensorSurface.ProtectedState => telemetry.ProtectedStateAsync(r,s,p,ct),
            SensorSurface.SensorSelfIntegrity => telemetry.SensorSelfIntegrityAsync(r,s,p,ct),
            _ => Task.FromResult<SensorEvidence?>(null)
        };
    }
}

public sealed class UserAssetSecurityTelemetryAdapter(IUserAssetSecurityTelemetry? telemetry = null) : ISensorEvidenceSource
{
    public Task<SensorEvidence?> CollectAsync(SensorEvaluationRequest r, SensorScope s, SensorSurface surface,
        SensorPolicy p, ProtectedUserRegistrySnapshot? registry, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (telemetry is null || s.Plane != SensorPlane.UserAssetSecurity || !ReferenceEquals(s.Request, r) ||
            registry is null || !ReferenceEquals(registry.Scope, s)) return Task.FromResult<SensorEvidence?>(null);
        return surface switch {
            SensorSurface.AccountAuthentication => telemetry.AccountAuthenticationAsync(s,p,registry,ct),
            SensorSurface.DevicePossession => telemetry.DevicePossessionAsync(s,p,registry,ct),
            SensorSurface.SessionIntegrity => telemetry.SessionIntegrityAsync(s,p,registry,ct),
            SensorSurface.TradingActivity => telemetry.TradingActivityAsync(s,p,registry,ct),
            SensorSurface.UnauthorizedTransfer => telemetry.UnauthorizedTransferAsync(s,p,registry,ct),
            SensorSurface.WithdrawalDestination => telemetry.WithdrawalDestinationAsync(s,p,registry,ct),
            _ => Task.FromResult<SensorEvidence?>(null)
        };
    }
}
