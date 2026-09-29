using System.Runtime.InteropServices;
using IMortal.TrustBroker.Providers;

namespace IMortal.TrustBroker.Providers.Linux;

public sealed class LinuxTpmProvider : ITrustProvider
{
    public string ProviderId => "linux-tpm2";

    public bool IsAvailable() =>
        OperatingSystem.IsLinux() && Detect().State != TrustProviderState.Unavailable;

    public TrustDetectionResult Detect()
    {
        if (!OperatingSystem.IsLinux())
            return new(TrustProviderState.Unavailable, ProviderId, false, false);

        bool hardwareDetected =
            File.Exists("/dev/tpmrm0") || File.Exists("/dev/tpm0");

        if (!hardwareDetected)
            return new(TrustProviderState.ProviderAvailable, ProviderId, false, false);

        return new(
            LinuxTpmReady() ? TrustProviderState.HardwareReady : TrustProviderState.HardwareDetected,
            ProviderId,
            true,
            true);
    }
    public TrustProviderCapabilities GetCapabilities() =>
        TrustProviderCapabilities.Detection |
        TrustProviderCapabilities.Enrollment |
        TrustProviderCapabilities.Authorization |
        TrustProviderCapabilities.Attestation |
        TrustProviderCapabilities.Signing |
        TrustProviderCapabilities.Revocation;

    public Task<TrustIdentityResult> EnrollAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustIdentityResult(false, null, "TPM_OPERATION_DISABLED"));

    public Task<TrustOperationResult> AuthorizeAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "TPM_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> AttestAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "TPM_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> SignAsync(AuthorizationRequest request, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "TPM_OPERATION_DISABLED", null));

    public Task<TrustOperationResult> RevokeAsync(AuthorizationRequest request, CancellationToken cancellationToken)
        => Task.FromResult(new TrustOperationResult(false, "TPM_OPERATION_DISABLED", null));

    private static bool LinuxTpmReady()
    {
        IntPtr context = IntPtr.Zero;
        try
        {
            nuint size = 0;
            uint status = Tss2TctiDeviceInit(IntPtr.Zero, ref size, null);
            if (status != 0 || size == 0)
                return false;

            context = Marshal.AllocHGlobal(checked((int)size));
            status = Tss2TctiDeviceInit(context, ref size, null);
            return status == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (context != IntPtr.Zero)
                Marshal.FreeHGlobal(context);
        }
    }

    [DllImport("libtss2-tcti-device.so.0", EntryPoint = "Tss2_Tcti_Device_Init")]
    private static extern uint Tss2TctiDeviceInit(
        IntPtr context,
        ref nuint size,
        string? configuration);
}
