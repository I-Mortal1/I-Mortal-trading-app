namespace IMortal.TrustBroker.Security.Sensors;

public sealed record SourceInventoryEntry(string CanonicalRelativePath, string Sha256, string FileIdentity, bool LinkOrReparsePoint);
public sealed class SourceInventorySnapshot
{
    public SourceInventorySnapshot(string scope, string snapshotRevision, bool stableSnapshot,
        IEnumerable<SourceInventoryEntry> entries)
    { Scope = scope; SnapshotRevision = snapshotRevision; StableSnapshot = stableSnapshot; Entries = Array.AsReadOnly(entries.ToArray()); }
    public string Scope { get; }
    public string SnapshotRevision { get; }
    public bool StableSnapshot { get; }
    public IReadOnlyList<SourceInventoryEntry> Entries { get; }
}
public sealed record SourceInventoryAcquisition(SourceInventorySnapshot Manifest, SourceInventorySnapshot Observed,
    string ProtectedProvenanceReference, DateTimeOffset ObservedAt, DateTimeOffset ValidUntil,
    bool WatcherOverflow, bool MissedEvents, bool InaccessibleFiles, bool ScanFailed);

public interface ISourceInventoryInfrastructure
{
    // Notifications trigger scans; periodic reconciliation must run even without events.
    // Bind open file handles/OS identities to an authenticated inventory generation,
    // no-follow/reparse-safe traversal, canonical paths and before/after file versions.
    // Unstable reads, inaccessible files or incomplete scans must never be a clean scan.
    Task<SourceInventoryAcquisition?> AcquireAsync(SensorScope scope, CancellationToken cancellation);
}
public interface ISourceManifestVerifier
{
    // Independently authenticate the manifest signature, scope, current policy,
    // anti-rollback state and observed snapshot provenance. Do NOT adopt changes.
    Task<bool> VerifyAsync(SensorScope scope, SensorPolicy policy, SourceInventoryAcquisition acquisition, CancellationToken cancellation);
    // Separate signed authorization for exact before/after inventory and policy transition.
    Task<bool> IsAuthorizedChangeAsync(SensorScope scope, SourceInventoryAcquisition acquisition, CancellationToken cancellation);
}

/// <summary>Pure inventory comparison. Hashes never imply attempted writes or authenticated change authorization.</summary>
public static class SourceInventoryComparison
{
    public static IReadOnlyList<SensorFinding> Compare(SourceInventorySnapshot expected, SourceInventorySnapshot observed)
    {
        var findings = new List<SensorFinding>();
        void Add(SensorCondition c) => findings.Add(new(SensorSurface.SourceIntegrity, c, ""));
        if (!expected.StableSnapshot || !observed.StableSnapshot || string.IsNullOrWhiteSpace(expected.SnapshotRevision) ||
            string.IsNullOrWhiteSpace(observed.SnapshotRevision)) { Add(SensorCondition.UnstableSnapshot); return findings.AsReadOnly(); }
        if (expected.Scope != observed.Scope) Add(SensorCondition.InventoryScopeChanged);
        Dictionary<string, SourceInventoryEntry> Index(SourceInventorySnapshot snapshot)
        {
            var result = new Dictionary<string, SourceInventoryEntry>(StringComparer.Ordinal);
            var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var identities = new HashSet<string>(StringComparer.Ordinal);
            foreach (var e in snapshot.Entries)
            {
                var p = e.CanonicalRelativePath;
                bool Reserved(string segment)
                {
                    var stem = segment.Split('.')[0].ToUpperInvariant();
                    return stem is "CON" or "PRN" or "AUX" or "NUL" ||
                        (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] is >= '1' and <= '9');
                }
                if (e.LinkOrReparsePoint || string.IsNullOrWhiteSpace(p) || p.StartsWith('/') || p.Contains('\\') || p.Contains(':') ||
                    p.Any(char.IsControl) || !p.IsNormalized(System.Text.NormalizationForm.FormC) ||
                    p.Split('/').Any(s => s is "" or "." or ".." || s.EndsWith('.') || s.EndsWith(' ') || Reserved(s)) ||
                    e.Sha256.Length != 64 || e.Sha256.Any(c => !Uri.IsHexDigit(c)) || string.IsNullOrWhiteSpace(e.FileIdentity) ||
                    !aliases.Add(p) || !identities.Add(e.FileIdentity)) throw new ArgumentException("Ambiguous or unsafe inventory");
                result.Add(p, e);
            }
            return result;
        }
        var before = Index(expected); var after = Index(observed);
        foreach (var e in before.Values)
        {
            if (after.TryGetValue(e.CanonicalRelativePath, out var current))
            { if (e.Sha256 != current.Sha256 || e.FileIdentity != current.FileIdentity) Add(SensorCondition.ContentModified); }
            else
            {
                var moved = after.Values.SingleOrDefault(n => n.FileIdentity == e.FileIdentity);
                if (moved is null) Add(SensorCondition.ContentDeleted);
                else { Add(SensorCondition.ContentRenamed); if (moved.Sha256 != e.Sha256) Add(SensorCondition.ContentModified); }
            }
        }
        foreach (var e in after.Values)
            if (!before.ContainsKey(e.CanonicalRelativePath) && !before.Values.Any(n => n.FileIdentity == e.FileIdentity)) Add(SensorCondition.ContentAdded);
        return findings.AsReadOnly();
    }
}

public sealed class SourceIntegritySensor : ISensorEvidenceSource
{
    private readonly ISourceInventoryInfrastructure _source;
    private readonly ISourceManifestVerifier _verifier;
    public SourceIntegritySensor(ISourceInventoryInfrastructure source, ISourceManifestVerifier verifier)
    { _source = source; _verifier = verifier; }
    public async Task<SensorEvidence?> CollectAsync(SensorEvaluationRequest request, SensorScope scope,
        SensorSurface surface, SensorPolicy policy, ProtectedUserRegistrySnapshot? registry, CancellationToken cancellation)
    {
        if (surface != SensorSurface.SourceIntegrity || scope.Plane != SensorPlane.PlatformIntegrity || registry is not null) return null;
        var a = await _source.AcquireAsync(scope, cancellation);
        if (a is null || !await _verifier.VerifyAsync(scope, policy, a, cancellation)) return null;
        var findings = SourceInventoryComparison.Compare(a.Manifest, a.Observed).ToList();
        void Gap(bool present, SensorCondition c) { if (present) findings.Add(new(surface, c, a.ProtectedProvenanceReference)); }
        Gap(a.WatcherOverflow, SensorCondition.WatcherOverflow); Gap(a.MissedEvents, SensorCondition.MissedEvents);
        Gap(a.InaccessibleFiles, SensorCondition.InaccessibleSurface); Gap(a.ScanFailed, SensorCondition.ScanFailure);
        if (findings.Count > 0 && await _verifier.IsAuthorizedChangeAsync(scope, a, cancellation))
            findings.Add(new(surface, SensorCondition.AuthorizedChangeObserved, a.ProtectedProvenanceReference));
        return new(request, scope, surface, a.ObservedAt, a.ValidUntil, policy.Version, a.ProtectedProvenanceReference,
            !a.WatcherOverflow && !a.MissedEvents && !a.InaccessibleFiles && !a.ScanFailed && a.Observed.StableSnapshot, findings);
    }
}
