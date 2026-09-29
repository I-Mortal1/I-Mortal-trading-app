namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed record AmdSevSnpRawEvidence(
    byte[] AttestationBytes,
    string ChallengeId,
    byte[] ChallengeBinding,
    string PlatformIdentityInput,
    byte[] MeasurementInput,
    byte[] VerifierCollateral);
