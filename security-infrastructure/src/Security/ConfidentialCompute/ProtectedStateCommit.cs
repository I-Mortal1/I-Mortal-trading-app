using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Describes the identity of a committed protected state.
///
/// This type records state identity only. It is not root trust, source
/// authority, signing authority, trading authority, or production authority.
/// </summary>
public sealed class ProtectedStateCommit
{
    private readonly byte[] _previousStateDigest;
    private readonly byte[] _resultingStateDigest;
    private readonly byte[] _authorizedChangesetDigest;

    public ProtectedStateCommit(
        long previousVersion,
        byte[] previousStateDigest,
        long resultingVersion,
        byte[] resultingStateDigest,
        byte[] authorizedChangesetDigest)
    {
        if (previousVersion < 0)
            throw new ArgumentOutOfRangeException(nameof(previousVersion));

        if (resultingVersion <= previousVersion)
            throw new ArgumentOutOfRangeException(
                nameof(resultingVersion),
                "Committed version must advance monotonically.");

        ArgumentNullException.ThrowIfNull(previousStateDigest);
        ArgumentNullException.ThrowIfNull(resultingStateDigest);
        ArgumentNullException.ThrowIfNull(authorizedChangesetDigest);

        if (previousStateDigest.Length == 0)
            throw new ArgumentException(
                "Previous state digest must not be empty.",
                nameof(previousStateDigest));

        if (resultingStateDigest.Length == 0)
            throw new ArgumentException(
                "Resulting state digest must not be empty.",
                nameof(resultingStateDigest));

        if (authorizedChangesetDigest.Length == 0)
            throw new ArgumentException(
                "Authorized changeset digest must not be empty.",
                nameof(authorizedChangesetDigest));

        PreviousVersion = previousVersion;
        ResultingVersion = resultingVersion;

        _previousStateDigest = (byte[])previousStateDigest.Clone();
        _resultingStateDigest = (byte[])resultingStateDigest.Clone();
        _authorizedChangesetDigest =
            (byte[])authorizedChangesetDigest.Clone();
    }

    public long PreviousVersion { get; }

    public long ResultingVersion { get; }

    public byte[] PreviousStateDigest =>
        (byte[])_previousStateDigest.Clone();

    public byte[] ResultingStateDigest =>
        (byte[])_resultingStateDigest.Clone();

    public byte[] AuthorizedChangesetDigest =>
        (byte[])_authorizedChangesetDigest.Clone();
}
