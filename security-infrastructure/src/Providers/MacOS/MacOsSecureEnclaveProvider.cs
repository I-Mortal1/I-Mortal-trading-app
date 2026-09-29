using System.Runtime.InteropServices;
using IMortal.TrustBroker.Providers;

namespace IMortal.TrustBroker.Providers.MacOS;

public sealed class MacOsSecureEnclaveProvider : ITrustProvider
{
    public string ProviderId => "macos-secure-enclave";

    public bool IsAvailable() => false;
    public TrustDetectionResult Detect()
    {
        if (!OperatingSystem.IsMacOS())
            return new(TrustProviderState.Unavailable, ProviderId, false, false);

        // Secure Enclave detection will be implemented through the native
        // Apple Security framework. Do not claim hardware readiness yet.
        if (!SecurityFrameworkAvailable())
            return new(TrustProviderState.Unavailable, ProviderId, false, false);

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
        => Task.FromResult(new TrustIdentityResult(false, null, "SECURE_ENCLAVE_OPERATION_DISABLED"));

    public Task<TrustOperationResult> AuthorizeAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "SECURE_ENCLAVE_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> AttestAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "SECURE_ENCLAVE_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> SignAsync(AuthorizationRequest request, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "SECURE_ENCLAVE_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> RevokeAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "SECURE_ENCLAVE_OPERATION_DISABLED", null));

    private static bool SecurityFrameworkAvailable()
    {
        if (!OperatingSystem.IsMacOS())
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
