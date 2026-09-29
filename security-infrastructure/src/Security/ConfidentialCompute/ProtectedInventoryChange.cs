using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Describes one explicitly declared change to the protected project inventory.
///
/// This type is descriptive only. Possession of an instance does not authorize
/// a source mutation, baseline promotion, project access, signing operation,
/// production operation, or any other security-sensitive action.
/// </summary>
public sealed class ProtectedInventoryChange
{
    public ProtectedInventoryChange(
        string relativePath,
        string classification,
        byte[] expectedPreviousSha256,
        byte[] expectedResultingSha256,
        long expectedResultingLength)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
            throw new ArgumentException(
                "Protected relative path is required.",
                nameof(relativePath));

        if (System.IO.Path.IsPathRooted(relativePath))
            throw new ArgumentException(
                "Protected path must be relative.",
                nameof(relativePath));

        if (relativePath.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException(
                "Path traversal is prohibited.",
                nameof(relativePath));

        if (string.IsNullOrWhiteSpace(classification))
            throw new ArgumentException(
                "Protected classification is required.",
                nameof(classification));

        if (expectedPreviousSha256 is null)
            throw new ArgumentNullException(nameof(expectedPreviousSha256));

        if (expectedResultingSha256 is null)
            throw new ArgumentNullException(nameof(expectedResultingSha256));

        if (expectedPreviousSha256.Length != 0 &&
            expectedPreviousSha256.Length != 32)
        {
            throw new ArgumentException(
                "Previous SHA-256 must be empty for an authorized addition or exactly 32 bytes.",
                nameof(expectedPreviousSha256));
        }

        if (expectedResultingSha256.Length != 0 &&
            expectedResultingSha256.Length != 32)
        {
            throw new ArgumentException(
                "Resulting SHA-256 must be empty for an authorized removal or exactly 32 bytes.",
                nameof(expectedResultingSha256));
        }

        if (expectedResultingLength < 0 &&
            expectedResultingSha256.Length != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedResultingLength));
        }

        RelativePath = relativePath;
        Classification = classification;
        _expectedPreviousSha256 = expectedPreviousSha256.ToArray();
        _expectedResultingSha256 = expectedResultingSha256.ToArray();
        ExpectedResultingLength = expectedResultingLength;
    }

    private readonly byte[] _expectedPreviousSha256;
    private readonly byte[] _expectedResultingSha256;

    public string RelativePath { get; }

    public string Classification { get; }

    public byte[] ExpectedPreviousSha256 =>
        _expectedPreviousSha256.ToArray();

    public byte[] ExpectedResultingSha256 =>
        _expectedResultingSha256.ToArray();

    public long ExpectedResultingLength { get; }

    public bool IsAddition =>
        _expectedPreviousSha256.Length == 0 &&
        _expectedResultingSha256.Length == 32;

    public bool IsModification =>
        _expectedPreviousSha256.Length == 32 &&
        _expectedResultingSha256.Length == 32;

    public bool IsRemoval =>
        _expectedPreviousSha256.Length == 32 &&
        _expectedResultingSha256.Length == 0;
}
