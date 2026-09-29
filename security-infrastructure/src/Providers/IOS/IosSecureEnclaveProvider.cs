using System.Runtime.InteropServices;
using IMortal.TrustBroker.Providers;

namespace IMortal.TrustBroker.Providers.IOS;

public sealed class IosSecureEnclaveProvider : ITrustProvider
{
    public string ProviderId => "ios-secure-enclave";

    public bool IsAvailable() => false;
    public TrustDetectionResult Detect()
    {
        if (!OperatingSystem.IsIOS())
            return new(TrustProviderState.Unavailable, ProviderId, false, false);

        // Native Secure Enclave detection requires the iOS application target.
        // Until that target is present, fail closed.
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
        => Task.FromResult(new TrustIdentityResult(false, null, "IOS_SECURE_ENCLAVE_OPERATION_DISABLED"));

    public Task<TrustOperationResult> AuthorizeAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "IOS_SECURE_ENCLAVE_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> AttestAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "IOS_SECURE_ENCLAVE_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> SignAsync(AuthorizationRequest request, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "IOS_SECURE_ENCLAVE_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> RevokeAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "IOS_SECURE_ENCLAVE_OPERATION_DISABLED", null));

    private static bool SecurityFrameworkAvailable()
    {
        if (!OperatingSystem.IsIOS())
            return false;

        try
        {
            return NativeLibrary.TryLoad(
                "/System/Library/Frameworks/Security.framework/Security",
                out IntPtr handle) && ReleaseLibrary(handle);
        }
        catch
        {
            return false;
        }
    }

    private static bool ReleaseLibrary(IntPtr handle)
    {
        if (handle == IntPtr.Zero)
            return false;

        NativeLibrary.Free(handle);
        return true;
    }
}
