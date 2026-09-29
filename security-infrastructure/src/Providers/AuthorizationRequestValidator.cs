namespace IMortal.TrustBroker.Providers;

/// <summary>
/// Performs side-effect-free structural and temporal validation of an
/// authorization request.
///
/// This validator does not perform replay detection, nonce persistence,
/// hardware operations, identity enrollment, user authorization, or
/// production authorization.
/// </summary>
public static class AuthorizationRequestValidator
{
    public static AuthorizationRequestValidationResult Validate(
        AuthorizationRequest? request,
        DateTimeOffset now)
    {
        if (request is null)
            return Invalid("REQUEST_REQUIRED");

        if (string.IsNullOrWhiteSpace(request.RequestId))
            return Invalid("REQUEST_ID_REQUIRED");

        if (string.IsNullOrWhiteSpace(request.Operation))
            return Invalid("OPERATION_REQUIRED");

        if (string.IsNullOrWhiteSpace(request.DeviceIdentity))
            return Invalid("DEVICE_IDENTITY_REQUIRED");

        if (string.IsNullOrWhiteSpace(request.Nonce))
            return Invalid("NONCE_REQUIRED");

        if (string.IsNullOrWhiteSpace(request.PolicyVersion))
            return Invalid("POLICY_VERSION_REQUIRED");

        if (string.IsNullOrWhiteSpace(request.AuthorizationState))
            return Invalid("AUTHORIZATION_STATE_REQUIRED");

        if (request.ExpiresAt <= now)
            return Invalid("REQUEST_EXPIRED");

        return new AuthorizationRequestValidationResult(
            true,
            null);
    }

    private static AuthorizationRequestValidationResult Invalid(
        string errorCode) =>
        new(false, errorCode);
}

public sealed record AuthorizationRequestValidationResult(
    bool Success,
    string? ErrorCode);
