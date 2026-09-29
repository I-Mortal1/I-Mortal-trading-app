namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Immutable result from the umbrella composition boundary.
///
/// This object contains a decision only. It contains no key material,
/// credentials, USB material, source material, or attestation evidence.
/// </summary>
public sealed record UmbrellaRootAuthorizationResult(
    UmbrellaRootAuthorizationState State,
    UmbrellaRootDenialReason DenialReason)
{
    public bool IsSatisfied =>
        State == UmbrellaRootAuthorizationState.Satisfied;

    public static UmbrellaRootAuthorizationResult Denied(
        UmbrellaRootDenialReason reason)
        => new(
            UmbrellaRootAuthorizationState.Denied,
            reason);

    internal static UmbrellaRootAuthorizationResult Satisfied()
        => new(
            UmbrellaRootAuthorizationState.Satisfied,
            UmbrellaRootDenialReason.None);
}