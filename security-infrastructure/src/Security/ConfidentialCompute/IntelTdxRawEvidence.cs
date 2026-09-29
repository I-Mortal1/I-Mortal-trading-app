namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed record IntelTdxRawEvidence(
    byte[] AttestationBytes,
    string ChallengeId,
    byte[] ChallengeBinding,
    string PlatformIdentityInput,
    byte[] MeasurementInput,
    byte[] VerifierCollateral);
