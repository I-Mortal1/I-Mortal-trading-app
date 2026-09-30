namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>Requested scope, never evidence of authority. Trusted policy must approve every field.</summary>
public sealed record AuthorizationIntent(
    UmbrellaSecurityDomain Domain,
    DeveloperSourceAuthorityMode DeveloperMode,
    string Operation,
    string Workload,
    ConfidentialPlatformClass Platform,
    string DeveloperIdentity = "",
    long IdentityVersion = 0);

/// <summary>Fresh root-owned identity. Reference ownership is not provenance.</summary>
public sealed class RootEvaluationRequest
{
    internal RootEvaluationRequest(AuthorizationIntent intent, DateTimeOffset time)
    { Intent = intent; EvaluationTime = time; }
    public AuthorizationIntent Intent { get; }
    public DateTimeOffset EvaluationTime { get; }
}

/// <summary>
/// Issuance record supplied by the independently provisioned lifecycle authority.
/// Construction alone proves nothing. The authority must authenticate its durable
/// issuance record, nonce, required policy, and (for developers) current enrollment.
/// No plaintext email or key material is accepted here.
/// </summary>
public sealed class IssuedAuthorization
{
    public IssuedAuthorization(RootEvaluationRequest owner, AttestationChallenge challenge,
        ProjectIntegrityPolicy requiredPolicy, ProtectedDeveloperIdentity? developerIdentity = null)
    {
        Owner = owner ?? throw new ArgumentNullException(nameof(owner));
        Challenge = challenge ?? throw new ArgumentNullException(nameof(challenge));
        RequiredPolicy = requiredPolicy ?? throw new ArgumentNullException(nameof(requiredPolicy));
        DeveloperIdentity = developerIdentity;
    }
    public RootEvaluationRequest Owner { get; }
    public AttestationChallenge Challenge { get; }
    public ProjectIntegrityPolicy RequiredPolicy { get; }
    public ProtectedDeveloperIdentity? DeveloperIdentity { get; }
}

/// <summary>
/// Trusted issuance/replay boundary, not a caller-supplied approval flag.
/// TryIssue must authenticate independent policy, authorize the exact intent,
/// authenticate the current protected enrollment/version/custody/email commitment,
/// and durably register a fresh unpredictable nonce of at least 32 bytes.
/// IsCurrent must authenticate record ownership and all those bindings.
/// TryCommit must atomically revalidate trusted current time, exact request,
/// known issuance, expiry, policy/enrollment versions, bounded recovery attempts,
/// and the supplied availability observation's current authoritative revision;
/// then durably consume once. Unknown, stale, uncertain, or consumed records deny.
/// Commit ambiguity or crash denies, never retries approval; consumption may burn
/// an attempt even when no result reaches the caller. No in-memory implementation
/// is supplied. Implementations must coordinate availability revisions with their
/// authoritative observer; a last-second boolean check is insufficient.
/// </summary>
public interface IAuthorizationLifecycle
{
    bool TryIssue(RootEvaluationRequest request, out IssuedAuthorization? issued);
    bool IsCurrent(IssuedAuthorization issued);
    // Atomically reserve one bounded attempt in the durable issuance record before
    // contacting a USB/recovery proof provider. No default permissive accounting.
    bool TryBeginProofAttempt(IssuedAuthorization issued) => false;
    bool TryCommit(AuthorizationCommit commit);
}

public sealed class DenyAllAuthorizationLifecycle : IAuthorizationLifecycle
{
    public bool TryIssue(RootEvaluationRequest request, out IssuedAuthorization? issued)
    { issued = null; return false; }
    public bool IsCurrent(IssuedAuthorization issued) => false;
    public bool TryBeginProofAttempt(IssuedAuthorization issued) => false;
    public bool TryCommit(AuthorizationCommit commit) => false;
}

/// <summary>Only the root constructs a commit after all independent gates pass.</summary>
public sealed class AuthorizationCommit
{
    internal AuthorizationCommit(IssuedAuthorization issued, DeveloperAuthorityContext? developer)
    { Issued = issued; Developer = developer; }
    public IssuedAuthorization Issued { get; }
    public DeveloperAuthorityContext? Developer { get; }
}

/// <summary>
/// Authenticated acquisition AND platform cryptographic verification AND independently
/// trusted measurement policy for this exact issuance/request/workload/time. Must
/// validate signed report/quote, collateral, trust anchors, revocation/TCB policy,
/// and report-data challenge binding; flags/hashes/constructors are insufficient.
/// The supplied evidence must be immutable or snapshotted before verification.
/// No approving implementation is provided.
/// </summary>
public interface ITransactionTeeVerifier
{
    bool Verify(IssuedAuthorization issued, IConfidentialComputeEvidence evidence);
}

public interface ITransactionTeeEvidenceProvider
{
    IConfidentialComputeEvidence? Collect(IssuedAuthorization issued);
}

/// <summary>Explicitly provisioned composition. Missing dependencies always deny.</summary>
public sealed class AuthorizationFoundation
{
    public AuthorizationFoundation(IAuthorizationLifecycle? lifecycle = null,
        ITransactionTeeEvidenceProvider? teeProvider = null, ITransactionTeeVerifier? teeVerifier = null,
        IDeveloperAuthorityContextProducer? developerProducer = null)
    {
        Lifecycle = lifecycle ?? new DenyAllAuthorizationLifecycle();
        TeeProvider = teeProvider; TeeVerifier = teeVerifier; DeveloperProducer = developerProducer;
    }
    internal IAuthorizationLifecycle Lifecycle { get; }
    internal ITransactionTeeEvidenceProvider? TeeProvider { get; }
    internal ITransactionTeeVerifier? TeeVerifier { get; }
    internal IDeveloperAuthorityContextProducer? DeveloperProducer { get; }
}
