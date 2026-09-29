using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Describes one identified protected project state.
///
/// This type is descriptive only. Possession of a snapshot does not grant
/// authority to mutate, sign, commit, deploy, trade, or otherwise advance
/// protected project state.
/// </summary>
public sealed class ProtectedStateSnapshot
{
    private readonly byte[] _stateDigest;

    public ProtectedStateSnapshot(
        long version,
        byte[] stateDigest,
        int protectedInventoryCount)
    {
        if (version < 0)
            throw new ArgumentOutOfRangeException(nameof(version));

        ArgumentNullException.ThrowIfNull(stateDigest);

        if (stateDigest.Length == 0)
            throw new ArgumentException(
                "State digest must not be empty.",
                nameof(stateDigest));

        if (protectedInventoryCount < 0)
            throw new ArgumentOutOfRangeException(
                nameof(protectedInventoryCount));

        Version = version;
        _stateDigest = (byte[])stateDigest.Clone();
        ProtectedInventoryCount = protectedInventoryCount;
    }

    public long Version { get; }

    public int ProtectedInventoryCount { get; }

    public byte[] StateDigest => (byte[])_stateDigest.Clone();
}
