namespace IMortal.TrustBroker.Security.Provisioning;

public enum ProtectedRecordPurpose
{
    DeveloperIdentity, UsbCustody, DeveloperNotification, DeveloperRecovery,
    UserRegistry, IncidentSigning, IdentityEncryption, IdentityCommitment,
    DeveloperSigning, UserSigning, ApprovedPolicy, ExternalService
}

/// <summary>Random locator only, never a bearer capability or a derived personal identifier.</summary>
public sealed record ProtectedRecordReference(Guid Id)
{
    public override string ToString() => "[protected-record-reference]";
}

/// <summary>Claims until independently authorized. Owner is the exact root/sensor transaction request.</summary>
public sealed class ProtectedRecordRequest
{
    public ProtectedRecordRequest(object owner, Guid transactionId, string workload, string operation,
        string tenant, string user, string provider, ProtectedRecordPurpose purpose,
        ProtectedRecordReference reference, long version, DateTimeOffset evaluationTime)
    { Owner = owner; TransactionId = transactionId; Workload = workload; Operation = operation;
      Tenant = tenant; User = user; Provider = provider; Purpose = purpose; Reference = reference;
      Version = version; EvaluationTime = evaluationTime; }
    public object Owner { get; }
    public Guid TransactionId { get; }
    public string Workload { get; }
    public string Operation { get; }
    public string Tenant { get; }
    public string User { get; }
    public string Provider { get; }
    public ProtectedRecordPurpose Purpose { get; }
    public ProtectedRecordReference Reference { get; }
    public long Version { get; }
    public DateTimeOffset EvaluationTime { get; }
    public override string ToString() => "[protected-record-request]";
}

/// <summary>No plaintext payload. Receipt must be authenticated independently, not trusted by its name.</summary>
public sealed record ProtectedRecordReceipt(ProtectedRecordRequest Owner,
    ProtectedRecordReference Reference, string Provider, ProtectedRecordPurpose Purpose,
    long Version, DateTimeOffset ValidFrom, DateTimeOffset ExpiresAt, Guid ProtectedProofReference)
{
    public override string ToString() => "[protected-record-receipt]";
}

public interface IProtectedRecordProvider
{
    Task<ProtectedRecordReceipt?> ResolveAsync(ProtectedRecordRequest request, CancellationToken cancellation);
}

public interface IProtectedRecordTrust
{
    // Authenticate workload/operation/tenant/user/transaction, locator and provider BEFORE resolution.
    // Provision trust anchors independently: never trust a key supplied by the resolved record itself.
    Task<bool> AuthorizeAsync(ProtectedRecordRequest request, CancellationToken cancellation);
    // Authenticate receipt/proof, enrollment, exact provider/reference/purpose/version and transaction.
    // Consult authoritative current version, revocation and rollback state, with trusted current time.
    // Unavailability/ambiguous durability denies. No source-defined bootstrap credential.
    Task<bool> VerifyCurrentAsync(ProtectedRecordRequest request, ProtectedRecordReceipt receipt, CancellationToken cancellation);
}

/// <summary>Resolves protected handles only. Does not grant root authority or replace any security gate.</summary>
public sealed class ProtectedRecordAccess
{
    private readonly IProtectedRecordProvider? provider;
    private readonly IProtectedRecordTrust? trust;
    public ProtectedRecordAccess(IProtectedRecordProvider? provider = null, IProtectedRecordTrust? trust = null)
    { this.provider = provider; this.trust = trust; }
    public async Task<ProtectedRecordReceipt?> ResolveAsync(ProtectedRecordRequest request, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        try
        {
            if (request is null || request.Owner is null || request.TransactionId == Guid.Empty ||
                request.Reference is null || request.Reference.Id == Guid.Empty || request.Version <= 0 ||
                request.EvaluationTime == default || !Enum.IsDefined(request.Purpose) ||
                string.IsNullOrWhiteSpace(request.Workload) || string.IsNullOrWhiteSpace(request.Operation) ||
                string.IsNullOrWhiteSpace(request.Tenant) || string.IsNullOrWhiteSpace(request.Provider) ||
                ((request.Purpose is ProtectedRecordPurpose.UserRegistry or ProtectedRecordPurpose.UserSigning) && string.IsNullOrWhiteSpace(request.User)) ||
                provider is null || trust is null || !await trust.AuthorizeAsync(request, cancellation)) return null;
            var receipt = await provider.ResolveAsync(request, cancellation);
            cancellation.ThrowIfCancellationRequested();
            if (receipt is null || !ReferenceEquals(receipt.Owner, request) || receipt.Reference != request.Reference ||
                receipt.Provider != request.Provider || receipt.Purpose != request.Purpose || receipt.Version != request.Version ||
                receipt.ProtectedProofReference == Guid.Empty || receipt.ValidFrom == default ||
                receipt.ValidFrom > request.EvaluationTime || receipt.ExpiresAt <= request.EvaluationTime ||
                !await trust.VerifyCurrentAsync(request, receipt, cancellation)) return null;
            return receipt;
        }
        catch (OperationCanceledException) { throw; }
        catch { return null; } // No exception text or provider payload enters diagnostics.
    }
}

public interface IProtectedKeyOperations
{
    // Reauthorize and atomically revalidate the exact receipt at use, including expiry,
    // revocation/rotation, custody domain and operation. Never export raw private keys.
    // Incident, identity, developer and user keys MUST be independently provisioned.
    Task<byte[]?> SignAsync(ProtectedRecordReceipt key, ReadOnlyMemory<byte> message, CancellationToken cancellation);
    // Decryption uses a caller-owned mutable buffer. Caller must clear it with
    // CryptographicOperations.ZeroMemory after use; implementation clears intermediates.
    // No guaranteed managed-string erasure is claimed; never create a plaintext string.
    Task<int?> DecryptAsync(ProtectedRecordReceipt key, ReadOnlyMemory<byte> ciphertext, Memory<byte> plaintext, CancellationToken cancellation);
}

public interface IProtectedExternalServiceOperations
{
    // Credential use occurs inside the authenticated provider; no credential getter.
    // Endpoint, method and least-privilege operation are protected policy, not arbitrary URLs.
    // Revalidate current receipt and exact scope atomically at use; sanitize provider responses.
    Task<bool> ExecuteReadOnlyAsync(ProtectedRecordReceipt credential, CancellationToken cancellation);
}
