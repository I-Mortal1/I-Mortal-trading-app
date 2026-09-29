using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Represents the output of the controlled verification boundary.
///
/// Construction is internal so arbitrary external callers cannot manufacture
/// a successful verification result through the public API.
///
/// This object remains non-authoritative. Success does not itself grant
/// root trust or any operational authority.
/// </summary>
public sealed class VerifiedAttestationResult
{
    private VerifiedAttestationResult(
        bool succeeded,
        VerifiedConfidentialComputeEvidence? evidence,
        string denialReason)
    {
        if (succeeded && evidence is null)
        {
            throw new ArgumentException(
                "Successful verification requires verified evidence.",
                nameof(evidence));
        }

        if (!succeeded && evidence is not null)
        {
            throw new ArgumentException(
                "Denied verification must not carry verified evidence.",
                nameof(evidence));
        }

        Succeeded = succeeded;
        Evidence = evidence;
        DenialReason = denialReason ?? string.Empty;
    }

    public bool Succeeded { get; }

    public VerifiedConfidentialComputeEvidence? Evidence { get; }

    public string DenialReason { get; }

    internal static VerifiedAttestationResult Success(
        VerifiedConfidentialComputeEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        return new VerifiedAttestationResult(
            true,
            evidence,
            string.Empty);
    }

    internal static VerifiedAttestationResult Denied(
        string denialReason)
    {
        return new VerifiedAttestationResult(
            false,
            null,
            denialReason ?? string.Empty);
    }
}
