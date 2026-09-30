namespace IMortal.TrustBroker.Security.Sensors;

/// <summary>Signed data, not an authenticated policy until the independent verifier accepts it.</summary>
public sealed class SensorPolicy
{
    private readonly byte[] _signature;
    public SensorPolicy(string version, string signerReference, byte[] signature, TimeSpan maximumEvidenceAge)
    {
        if (string.IsNullOrWhiteSpace(version) || string.IsNullOrWhiteSpace(signerReference) ||
            signature is null || signature.Length == 0 || maximumEvidenceAge <= TimeSpan.Zero)
            throw new ArgumentException("Incomplete policy");
        Version = version; SignerReference = signerReference; _signature = (byte[])signature.Clone();
        MaximumEvidenceAge = maximumEvidenceAge;
    }
    public string Version { get; }
    public string SignerReference { get; }
    public byte[] Signature => (byte[])_signature.Clone();
    public TimeSpan MaximumEvidenceAge { get; }
}

public sealed class SignedSensorArtifact
{
    private readonly byte[] _measurement, _signature;
    public SignedSensorArtifact(string identity, string version, byte[] measurement, byte[] signature)
    { Identity = identity; Version = version; _measurement = (byte[])measurement.Clone(); _signature = (byte[])signature.Clone(); }
    public string Identity { get; }
    public string Version { get; }
    public byte[] Measurement => (byte[])_measurement.Clone();
    public byte[] Signature => (byte[])_signature.Clone();
}

public interface ISensorPolicyVerifier
{
    // Independently pinned trust anchor, signature, current authorized version and
    // anti-rollback/weakening checks. Sensors cannot authorize a policy transition.
    Task<bool> VerifyAsync(SensorScope scope, SensorPolicy policy, CancellationToken cancellation);
}
