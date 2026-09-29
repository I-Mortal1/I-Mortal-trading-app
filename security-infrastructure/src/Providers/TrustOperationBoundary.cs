namespace IMortal.TrustBroker.Providers;

/// <summary>
/// Mandatory validation boundary for future trust-provider operations.
///
/// Current phase intentionally performs no provider dispatch.
/// Every request is structurally and temporally validated first.
/// Valid requests remain fail-closed until replay protection,
/// authorization verification, and provider dispatch are separately enabled.
/// </summary>
public static class TrustOperationBoundary
{
    public static TrustOperationBoundaryResult ValidateForDispatch(
        AuthorizationRequest? request,
        DateTimeOffset now)
    {
        var validation =
            AuthorizationRequestValidator.Validate(
                request,
                now);

        if (!validation.Success)
        {
            return new TrustOperationBoundaryResult(
                false,
                validation.ErrorCode);
        }

        return new TrustOperationBoundaryResult(
            false,
            "PROVIDER_DISPATCH_DISABLED");
    }
}

public sealed record TrustOperationBoundaryResult(
    bool Success,
    string? ResultCode);
