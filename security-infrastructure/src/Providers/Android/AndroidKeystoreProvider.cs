using IMortal.TrustBroker.Providers;

namespace IMortal.TrustBroker.Providers.Android;

public sealed class AndroidKeystoreProvider : ITrustProvider
{
    public string ProviderId => "android-keystore";

    public bool IsAvailable() => OperatingSystem.IsAndroid() && Detect().State != TrustProviderState.Unavailable;
    public TrustDetectionResult Detect()
    {
        if (!OperatingSystem.IsAndroid())
            return new(TrustProviderState.Unavailable, ProviderId, false, false);

        // Native Android Keystore/KeyMint detection requires the Android
        // application target. Until verified, fail closed.
        return new(TrustProviderState.ProviderAvailable, ProviderId, false, false);
    }

    public TrustProviderCapabilities GetCapabilities() =>
        TrustProviderCapabilities.Detection |
        TrustProviderCapabilities.Enrollment |
        TrustProviderCapabilities.Authorization |
        TrustProviderCapabilities.Attestation |
        TrustProviderCapabilities.Signing |
        TrustProviderCapabilities.Revocation;

    public Task<TrustIdentityResult> EnrollAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustIdentityResult(false, null, "ANDROID_KEYSTORE_OPERATION_DISABLED"));

    public Task<TrustOperationResult> AuthorizeAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "ANDROID_KEYSTORE_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> AttestAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "ANDROID_KEYSTORE_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> SignAsync(AuthorizationRequest request, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "ANDROID_KEYSTORE_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> RevokeAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "ANDROID_KEYSTORE_OPERATION_DISABLED", null));
}
