using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Provides verifier trust-anchor material from a separately controlled
/// security source. The returned bytes are defensive copies owned by
/// the caller and do not themselves grant authority.
/// </summary>
public interface IManifestTrustAnchorProvider
{
    byte[] GetTrustAnchor(
        ConfidentialPlatformClass platformClass);
}