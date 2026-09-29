namespace IMortal.TrustBroker.Providers;

public interface ITrustProvider
{
    string ProviderId { get; }

    bool IsAvailable();
    TrustDetectionResult Detect();

    TrustProviderCapabilities GetCapabilities();

    Task<TrustIdentityResult> EnrollAsync(
        AuthorizationRequest request,
        CancellationToken cancellationToken);

    Task<TrustOperationResult> AuthorizeAsync(
        AuthorizationRequest request,
        CancellationToken cancellationToken);

    Task<TrustOperationResult> AttestAsync(
        AuthorizationRequest request,
        CancellationToken cancellationToken);

    Task<TrustOperationResult> SignAsync(
        AuthorizationRequest request,
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken);

    Task<TrustOperationResult> RevokeAsync(
        AuthorizationRequest request,
        CancellationToken cancellationToken);
}
