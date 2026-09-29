namespace IMortal.TrustBroker.Security;

public sealed record SecurityPolicyReference
{
    public string Version { get; }
    public string Sha256 { get; }

    public SecurityPolicyReference(
        string version,
        string sha256)
    {
        if (string.IsNullOrWhiteSpace(version))
            throw new ArgumentException(
                "Security policy version is required.",
                nameof(version));

        if (string.IsNullOrWhiteSpace(sha256) ||
            sha256.Length != 64 ||
            !sha256.All(c =>
                (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f')))
            throw new ArgumentException(
                "Security policy SHA-256 must be exactly 64 lowercase hexadecimal characters.",
                nameof(sha256));

        Version = version;
        Sha256 = sha256;
    }
}
