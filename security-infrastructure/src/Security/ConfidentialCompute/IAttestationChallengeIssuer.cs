namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IAttestationChallengeIssuer
{
    AttestationChallenge Issue(
        ConfidentialPlatformClass expectedPlatform,
        string workloadBinding);
}
