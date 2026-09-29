namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Independently verifies manifest provenance. A true result represents
/// provenance verification only; it grants no root, source, trading,
/// production, or provider-dispatch authority.
/// </summary>
public interface ICustodyManifestProvenanceVerifier
{
    bool Verify(
        CustodyManifestDescriptor manifest,
        CustodyManifestProvenance provenance,
        ConfidentialSecurityBoundaryIdentity expectedBoundary);
}