using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Describes a proposed transition between two protected inventory states.
///
/// This object is not authorization and cannot promote a baseline.
/// Actual transition authority remains inside the confidential security
/// boundary and must satisfy the independent security gates.
/// </summary>
public sealed class ProtectedStateTransition
{
    public ProtectedStateTransition(
        long previousVersion,
        long resultingVersion,
        byte[] previousStateDigest,
        byte[] authorizedChangesetDigest,
        byte[] resultingStateDigest,
        IReadOnlyList<ProtectedInventoryChange> changes)
    {
        if (previousVersion < 0)
            throw new ArgumentOutOfRangeException(nameof(previousVersion));

        if (resultingVersion <= previousVersion)
            throw new ArgumentException(
                "Resulting version must advance the protected state.",
                nameof(resultingVersion));

        ArgumentNullException.ThrowIfNull(previousStateDigest);
        ArgumentNullException.ThrowIfNull(authorizedChangesetDigest);
        ArgumentNullException.ThrowIfNull(resultingStateDigest);
        ArgumentNullException.ThrowIfNull(changes);

        if (previousStateDigest.Length != 32)
            throw new ArgumentException(
                "Previous state digest must be SHA-256.",
                nameof(previousStateDigest));

        if (authorizedChangesetDigest.Length != 32)
            throw new ArgumentException(
                "Authorized changeset digest must be SHA-256.",
                nameof(authorizedChangesetDigest));

        if (resultingStateDigest.Length != 32)
            throw new ArgumentException(
                "Resulting state digest must be SHA-256.",
                nameof(resultingStateDigest));

        if (changes.Count == 0)
            throw new ArgumentException(
                "At least one explicitly declared protected change is required.",
                nameof(changes));

        PreviousVersion = previousVersion;
        ResultingVersion = resultingVersion;

        _previousStateDigest = previousStateDigest.ToArray();
        _authorizedChangesetDigest = authorizedChangesetDigest.ToArray();
        _resultingStateDigest = resultingStateDigest.ToArray();

        _changes = changes.ToArray();
    }

    private readonly byte[] _previousStateDigest;
    private readonly byte[] _authorizedChangesetDigest;
    private readonly byte[] _resultingStateDigest;
    private readonly ProtectedInventoryChange[] _changes;

    public long PreviousVersion { get; }

    public long ResultingVersion { get; }

    public byte[] PreviousStateDigest =>
        _previousStateDigest.ToArray();

    public byte[] AuthorizedChangesetDigest =>
        _authorizedChangesetDigest.ToArray();

    public byte[] ResultingStateDigest =>
        _resultingStateDigest.ToArray();

    public IReadOnlyList<ProtectedInventoryChange> Changes =>
        Array.AsReadOnly(_changes);
}
