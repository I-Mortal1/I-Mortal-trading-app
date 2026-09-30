using IMortal.TrustBroker.Security.Provisioning;

namespace IMortal.TrustBroker.Security.Sensors;

public interface INotificationRecordLocator
{
    // Independently protected enrollment directory supplies current random locator,
    // authorized provider/version and exact scope. Never look up by a source email.
    // Developer notification and developer recovery are disjoint purposes/records.
    Task<ProtectedRecordRequest?> LocateAsync(SensorScope scope, NotificationPurpose purpose,
        ProtectedUserRegistrySnapshot? registry, CancellationToken cancellation);
}

/// <summary>No enrollment or delivery. Missing provisioning explicitly returns no destination.</summary>
public sealed class ProtectedNotificationEnrollment : INotificationEnrollmentVerifier
{
    private readonly INotificationRecordLocator? locator;
    private readonly ProtectedRecordAccess access;
    public ProtectedNotificationEnrollment(INotificationRecordLocator? locator = null, ProtectedRecordAccess? access = null)
    { this.locator = locator; this.access = access ?? new(); }
    public async Task<NotificationEnrollment?> ResolveAsync(SensorScope scope, NotificationPurpose purpose,
        ProtectedUserRegistrySnapshot? registry, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        try
        {
            if (scope is null || locator is null || !Enum.IsDefined(purpose) ||
                (purpose == NotificationPurpose.DeveloperSecurityReport) != (scope.Plane == SensorPlane.PlatformIntegrity) ||
                (purpose == NotificationPurpose.UserSecurityReport && (registry is null || !ReferenceEquals(registry.Scope, scope)))) return null;
            var request = await locator.LocateAsync(scope, purpose, registry, cancellation);
            var expected = purpose == NotificationPurpose.DeveloperSecurityReport
                ? ProtectedRecordPurpose.DeveloperNotification : ProtectedRecordPurpose.UserRegistry;
            if (request is null || !ReferenceEquals(request.Owner, scope.Request) || request.TransactionId != scope.Request.EvaluationId ||
                request.Tenant != scope.TenantId || request.User != scope.UserId || request.Workload != scope.Request.Workload ||
                request.Operation != "security-notification" || request.Purpose != expected || request.EvaluationTime != scope.Request.EvaluationTime ||
                (registry is not null && (request.Version != registry.Version || request.Reference.Id.ToString("D") != registry.VerifiedNotificationEmailReference))) return null;
            var receipt = await access.ResolveAsync(request, cancellation);
            return receipt is null ? null : new(scope, receipt.Reference.Id.ToString("D"), receipt.Version.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        catch (OperationCanceledException) { throw; }
        catch { return null; }
    }
}
