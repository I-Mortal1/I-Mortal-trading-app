using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class ProtectedStateCommitRequest
{
    private readonly byte[] _expectedCurrentStateDigest;
    private readonly byte[] _authorizedChangesetDigest;
    private readonly byte[] _resultingStateDigest;

    public ProtectedStateCommitRequest(
        PreparedProtectedStateTransition preparedTransition,
        long expectedCurrentVersion,
        byte[] expectedCurrentStateDigest,
        byte[] authorizedChangesetDigest,
        long resultingVersion,
        byte[] resultingStateDigest,
        ConfidentialSecurityBoundaryIdentity boundaryIdentity)
    {
        PreparedTransition = preparedTransition
            ?? throw new ArgumentNullException(nameof(preparedTransition));

        if (expectedCurrentVersion < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedCurrentVersion));
        }

        if (resultingVersion <= expectedCurrentVersion)
        {
            throw new ArgumentOutOfRangeException(
                nameof(resultingVersion));
        }

        _expectedCurrentStateDigest = CopyRequired(
            expectedCurrentStateDigest,
            nameof(expectedCurrentStateDigest));

        _authorizedChangesetDigest = CopyRequired(
            authorizedChangesetDigest,
            nameof(authorizedChangesetDigest));

        _resultingStateDigest = CopyRequired(
            resultingStateDigest,
            nameof(resultingStateDigest));

        BoundaryIdentity = boundaryIdentity
            ?? throw new ArgumentNullException(nameof(boundaryIdentity));

        ExpectedCurrentVersion = expectedCurrentVersion;
        ResultingVersion = resultingVersion;
    }

    public PreparedProtectedStateTransition PreparedTransition { get; }

    public long ExpectedCurrentVersion { get; }

    public byte[] ExpectedCurrentStateDigest =>
        (byte[])_expectedCurrentStateDigest.Clone();

    public byte[] AuthorizedChangesetDigest =>
        (byte[])_authorizedChangesetDigest.Clone();

    public long ResultingVersion { get; }

    public byte[] ResultingStateDigest =>
        (byte[])_resultingStateDigest.Clone();

    public ConfidentialSecurityBoundaryIdentity BoundaryIdentity { get; }

    private static byte[] CopyRequired(
        byte[] value,
        string parameterName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(parameterName);
        }

        if (value.Length == 0)
        {
            throw new ArgumentException(
                "Digest must not be empty.",
                parameterName);
        }

        return (byte[])value.Clone();
    }
}
