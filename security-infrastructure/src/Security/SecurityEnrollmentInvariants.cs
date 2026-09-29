namespace IMortal.TrustBroker.Security;

public static class SecurityEnrollmentInvariants
{
    public static void AssertSafe(
        UserSecurityProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        if (profile.ProductionAuthorized)
            throw new InvalidOperationException(
                "F21 registration cannot authorize production.");

        if (profile.EnrollmentState >=
            SecurityEnrollmentState.ProductionAuthorized)
            throw new InvalidOperationException(
                "F21 registration cannot transition to production authorization.");

        if (string.IsNullOrWhiteSpace(
                profile.SecurityInstanceId))
            throw new InvalidOperationException(
                "Security instance identity is required.");

        if (profile.SecurityInstanceId.Length != 64)
            throw new InvalidOperationException(
                "Security instance identity must be SHA-256 sized.");

        if (string.IsNullOrWhiteSpace(
                profile.RegistrationNonceHash))
            throw new InvalidOperationException(
                "Registration nonce must never be persisted in plaintext.");
    }
}
