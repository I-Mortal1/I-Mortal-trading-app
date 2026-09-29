namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Result state for the I-Mortal Security Umbrella root.
///
/// Denied is the default. No platform provider can manufacture Satisfied.
/// </summary>
public enum UmbrellaRootAuthorizationState
{
    Denied = 0,
    Satisfied = 1
}