namespace IMortal.TrustBroker.Providers;

public sealed record AuthorizationRequest(
    string RequestId,
    string Operation,
    string DeviceIdentity,
    string Nonce,
    DateTimeOffset ExpiresAt,
    string PolicyVersion,
    string AuthorizationState);

public sealed record TrustIdentityResult(
    bool Success,
    string? PublicIdentity,
    string? ErrorCode);

public sealed record TrustOperationResult(
    bool Success,
    string? ResultCode,
    byte[]? PublicResult);
