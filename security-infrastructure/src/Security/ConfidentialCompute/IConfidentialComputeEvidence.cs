namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IConfidentialComputeEvidence
{
    ConfidentialEvidenceOrigin Origin { get; }
    ConfidentialPlatformClass PlatformClass { get; }

    bool TeeBoundaryPresent { get; }
    bool RemoteAttestationPresent { get; }

    DateTimeOffset AttestationIssuedAt { get; }
    DateTimeOffset AttestationExpiresAt { get; }

    string Measurement { get; }
    string MeasurementPolicyId { get; }
    string WorkloadIdentity { get; }
    string PlatformIdentity { get; }
    string SecurityPolicyId { get; }
    string SignedArtifactDigest { get; }
}
