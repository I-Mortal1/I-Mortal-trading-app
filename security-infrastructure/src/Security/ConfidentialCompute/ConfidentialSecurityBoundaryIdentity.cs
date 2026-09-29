using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Non-authoritative identity metadata for an attested confidential workload.
/// Possession of this value grants no trust or capability.
/// </summary>
public sealed class ConfidentialSecurityBoundaryIdentity
{
    public ConfidentialSecurityBoundaryIdentity(
        string workloadIdentity,
        string measurement,
        ConfidentialPlatformClass platformClass)
    {
        if (string.IsNullOrWhiteSpace(workloadIdentity))
        {
            throw new ArgumentException(
                "Workload identity is required.",
                nameof(workloadIdentity));
        }

        if (string.IsNullOrWhiteSpace(measurement))
        {
            throw new ArgumentException(
                "Measurement is required.",
                nameof(measurement));
        }

        WorkloadIdentity = workloadIdentity;
        Measurement = measurement;
        PlatformClass = platformClass;
    }

    public string WorkloadIdentity { get; }

    public string Measurement { get; }

    public ConfidentialPlatformClass PlatformClass { get; }
}