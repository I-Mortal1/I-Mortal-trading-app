namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Marker contract for evidence producers owned by the confidential
/// security boundary.
///
/// Implementation of this interface alone grants no authority.
/// Concrete producers must remain gated by the authoritative
/// confidential-compute verification chain.
/// </summary>
public interface ITypedVerificationEvidenceProducer
{
    ConfidentialSecurityBoundaryIdentity BoundaryIdentity { get; }
}
