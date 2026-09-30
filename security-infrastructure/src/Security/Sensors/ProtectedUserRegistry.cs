namespace IMortal.TrustBroker.Security.Sensors;

public sealed record VerifiedDestination(string AccountId, string Network, string Address,
    string ControlEvidenceReference, string ControlScope, bool Authorized);

/// <summary>Protected registry snapshot claims; the independent registry boundary authenticates them.</summary>
public sealed class ProtectedUserRegistrySnapshot
{
    public ProtectedUserRegistrySnapshot(SensorScope scope, long version, string provenanceReference,
        string verifiedNotificationEmailReference, IEnumerable<string> accounts, IEnumerable<VerifiedDestination> destinations)
    { Scope = scope; Version = version; ProvenanceReference = provenanceReference;
      VerifiedNotificationEmailReference = verifiedNotificationEmailReference;
      Accounts = Array.AsReadOnly(accounts.ToArray()); Destinations = Array.AsReadOnly(destinations.ToArray()); }
    public SensorScope Scope { get; }
    public long Version { get; }
    public string ProvenanceReference { get; }
    public string VerifiedNotificationEmailReference { get; }
    public IReadOnlyList<string> Accounts { get; }
    public IReadOnlyList<VerifiedDestination> Destinations { get; }
}
public interface IProtectedUserRegistry
{
    // Authenticate tenant/user, protected enrollment provenance, current version,
    // verified notification enrollment, linked accounts, chain and wallet/control
    // scope. No plaintext credentials, recovery enrollment or write API.
    Task<ProtectedUserRegistrySnapshot?> ReadAsync(SensorScope scope, CancellationToken cancellation);
    Task<bool> VerifyCurrentAsync(ProtectedUserRegistrySnapshot registry, CancellationToken cancellation);
}

public enum AssetMovementKind { Trade, InternalTransfer, Withdrawal, Fee, Settlement }
public sealed record AssetMovement(string TenantId, string UserId, string ProviderId, string AccountId,
    string EventId, long Sequence, string ProvenanceReference, bool Reconciled, AssetMovementKind Kind,
    string OperationId, string Asset, decimal Amount, string Destination, string Network,
    string? BlockchainTransactionId);
public sealed record AssetOperationAuthorization(string TenantId, string UserId, string AccountId,
    string OperationId, string Asset, decimal Amount, string Destination, string Network,
    DateTimeOffset ExpiresAt, bool ExplicitlyDenied = false);
public enum TransferAssessment { MatchedAuthorization, ConfirmedViolation, Suspicious, InsufficientEvidence }

public interface IAssetActivityProvenanceVerifier
{
    // Authenticate read-only provider/account binding and sequence/reconciliation,
    // and independently recorded authorization (including external/third-party scope).
    Task<bool> VerifyAsync(SensorScope scope, AssetMovement movement,
        AssetOperationAuthorization? authorization, CancellationToken cancellation);
}

/// <summary>
/// Pure comparison after external provenance verification. Not an authorization gate.
/// Absence of a local record cannot establish illicit activity outside I-Mortal.
/// A real adapter must authenticate external/third-party authorization sources too.
/// </summary>
public static class TransferCorrelation
{
    public static async Task<TransferAssessment> EvaluateAsync(SensorScope scope, AssetMovement movement,
        AssetOperationAuthorization? authorization, DateTimeOffset time,
        IAssetActivityProvenanceVerifier? verifier, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        try
        {
        if (scope is null || scope.Plane != SensorPlane.UserAssetSecurity || movement is null ||
            scope.TenantId != movement.TenantId || scope.UserId != movement.UserId || time != scope.Request.EvaluationTime ||
            verifier is null || !await verifier.VerifyAsync(scope, movement, authorization, cancellation) ||
            !movement.Reconciled || time == default ||
            movement.Amount <= 0 || string.IsNullOrWhiteSpace(movement.ProvenanceReference) ||
            movement.Kind is not (AssetMovementKind.Withdrawal or AssetMovementKind.InternalTransfer) || authorization is null)
            return TransferAssessment.InsufficientEvidence;
        if (authorization.TenantId != movement.TenantId || authorization.UserId != movement.UserId ||
            authorization.AccountId != movement.AccountId || authorization.OperationId != movement.OperationId)
            return TransferAssessment.InsufficientEvidence;
        if (authorization.ExplicitlyDenied) return TransferAssessment.ConfirmedViolation;
        return authorization.ExpiresAt > time && authorization.Asset == movement.Asset &&
            authorization.Amount == movement.Amount && authorization.Destination == movement.Destination &&
            authorization.Network == movement.Network ? TransferAssessment.MatchedAuthorization : TransferAssessment.Suspicious;
        }
        catch (OperationCanceledException) { throw; }
        catch { return TransferAssessment.InsufficientEvidence; }
    }
}
