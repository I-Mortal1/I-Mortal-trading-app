using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Describes a prepared but uncommitted protected-state transition.
///
/// A prepared transition is non-authoritative. It cannot itself advance the
/// canonical protected state and must not be interpreted as authorization.
/// </summary>
public sealed class PreparedProtectedStateTransition
{
    private readonly byte[] _previousStateDigest;
    private readonly byte[] _authorizedChangesetDigest;
    private readonly byte[] _resultingStateDigest;

    public PreparedProtectedStateTransition(
        long previousVersion,
        byte[] previousStateDigest,
        byte[] authorizedChangesetDigest,
        long resultingVersion,
        byte[] resultingStateDigest)
    {
        if (previousVersion < 0)
            throw new ArgumentOutOfRangeException(nameof(previousVersion));

        if (resultingVersion <= previousVersion)
            throw new ArgumentOutOfRangeException(
                nameof(resultingVersion),
                "Resulting version must be greater than previous version.");

        ArgumentNullException.ThrowIfNull(previousStateDigest);
        ArgumentNullException.ThrowIfNull(authorizedChangesetDigest);
        ArgumentNullException.ThrowIfNull(resultingStateDigest);

        if (previousStateDigest.Length == 0)
            throw new ArgumentException(
                "Previous state digest must not be empty.",
                nameof(previousStateDigest));

        if (authorizedChangesetDigest.Length == 0)
            throw new ArgumentException(
                "Authorized changeset digest must not be empty.",
                nameof(authorizedChangesetDigest));

        if (resultingStateDigest.Length == 0)
            throw new ArgumentException(
                "Resulting state digest must not be empty.",
                nameof(resultingStateDigest));

        PreviousVersion = previousVersion;
        ResultingVersion = resultingVersion;

        _previousStateDigest = (byte[])previousStateDigest.Clone();
        _authorizedChangesetDigest =
            (byte[])authorizedChangesetDigest.Clone();
        _resultingStateDigest = (byte[])resultingStateDigest.Clone();
    }

    public long PreviousVersion { get; }

    public long ResultingVersion { get; }

    public byte[] PreviousStateDigest =>
        (byte[])_previousStateDigest.Clone();

    public byte[] AuthorizedChangesetDigest =>
        (byte[])_authorizedChangesetDigest.Clone();

    public byte[] ResultingStateDigest =>
        (byte[])_resultingStateDigest.Clone();
}
