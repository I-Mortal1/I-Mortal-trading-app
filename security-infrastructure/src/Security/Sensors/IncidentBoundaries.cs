namespace IMortal.TrustBroker.Security.Sensors;

public sealed record IncidentCheckpoint(Guid EvaluationId, string TenantId, string UserId,
    SensorPlane Plane, string PolicyVersion, string FindingsDigest, string ProtectedCheckpointReference);

/// <summary>Content binding only; authentic signatures/chain validation remain external.</summary>
public static class IncidentDigest
{
    public static string Compute(IReadOnlyList<SensorFinding> findings)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, new System.Text.UTF8Encoding(false, true), true);
        writer.Write("I-MORTAL/SENSOR-INCIDENT/V1"); writer.Write(findings.Count);
        foreach (var finding in findings)
        { writer.Write((int)finding.Surface); writer.Write((int)finding.Condition); writer.Write(finding.ProtectedEventReference); }
        writer.Flush();
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream.ToArray()));
    }
}

public interface IIncidentLedger
{
    // Durable, append-only/tamper-evident, tenant-scoped, idempotent by evaluation id.
    // Authenticate prior checkpoint/sequence, include every finding and policy version,
    // reject rollback/forks. No in-memory ledger is supplied as production protection.
    Task<IncidentCheckpoint?> AppendAsync(SensorScope scope, SensorPolicy policy,
        IReadOnlyList<SensorFinding> findings, CancellationToken cancellation);
    // Append a separate status event linked to the immutable original checkpoint;
    // never rewrite it. Default absence is explicitly reported as an audit gap.
    Task<bool> RecordNotificationFailureAsync(IncidentCheckpoint checkpoint, CancellationToken cancellation) => Task.FromResult(false);
}
public interface IIndependentSensorMonitor
{
    // A separately trusted observer must verify sensor artifact signature, running
    // measurement, heartbeat, enabled collection, identity, authorized config/policy,
    // audit delivery and checkpoint chain. Colocation/self-report is insufficient.
    Task<bool> VerifyAsync(SensorScope scope, SensorPolicy policy, SignedSensorArtifact artifact,
        IncidentCheckpoint? checkpoint, CancellationToken cancellation);
}

public sealed record NotificationEnrollment(SensorScope Scope, string ProtectedDestinationReference, string Version);

public interface INotificationEnrollmentVerifier
{
    // Requested destination is not enrollment or identity. Verify existing protected
    // enrollment and authorized version; never create/change it during evaluation.
    Task<NotificationEnrollment?> ResolveAsync(SensorScope scope, NotificationPurpose purpose,
        ProtectedUserRegistrySnapshot? registry, CancellationToken cancellation);
}
public interface ISecurityNotificationOutbox
{
    // Enqueue protected incident/checkpoint references only; idempotent, scoped.
    // This is not email delivery. External delivery requires separate provisioning.
    Task<bool> EnqueueAsync(NotificationEnrollment enrollment, IncidentCheckpoint checkpoint, CancellationToken cancellation);
}

public enum NotificationPurpose { DeveloperSecurityReport, UserSecurityReport }
