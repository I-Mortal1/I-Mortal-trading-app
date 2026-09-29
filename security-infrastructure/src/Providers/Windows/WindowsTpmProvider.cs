using System.Runtime.InteropServices;
using IMortal.TrustBroker.Providers;

namespace IMortal.TrustBroker.Providers.Windows;

public sealed class WindowsTpmProvider : ITrustProvider
{
    private const string PlatformCryptoProvider = "Microsoft Platform Crypto Provider";

    public string ProviderId => "windows-tpm2";

    public bool IsAvailable() =>
        OperatingSystem.IsWindows() && Detect().State != TrustProviderState.Unavailable;

    public TrustDetectionResult Detect()
    {
        if (!OperatingSystem.IsWindows())
            return new(TrustProviderState.Unavailable, ProviderId, false, false);

        try
        {
            if (!CngProviderAvailable(PlatformCryptoProvider))
                return new(TrustProviderState.Unavailable, ProviderId, false, false);

            return new(
                TbsReady() ? TrustProviderState.HardwareReady : TrustProviderState.HardwareDetected,
                ProviderId,
                true,
                true);
        }
        catch
        {
            return new(TrustProviderState.Unavailable, ProviderId, false, false);
        }
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

    private static bool CngProviderAvailable(string providerName)
    {
        uint status = NCryptEnumStorageProviders(
            out int count,
            out IntPtr providers,
            0);

        if (status != 0 || providers == IntPtr.Zero || count <= 0)
            return false;

        try
        {
            int size = Marshal.SizeOf<NCryptProviderName>();

            for (int i = 0; i < count; i++)
            {
                IntPtr current = IntPtr.Add(providers, i * size);
                var provider = Marshal.PtrToStructure<NCryptProviderName>(current);

                if (provider.Name != IntPtr.Zero &&
                    string.Equals(
                        Marshal.PtrToStringUni(provider.Name),
                        providerName,
                        StringComparison.Ordinal))
                    return true;
            }

            return false;
        }
        finally
        {
            NCryptFreeBuffer(providers);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NCryptProviderName
    {
        public IntPtr Name;
        public IntPtr Comment;
    }

    [DllImport("ncrypt.dll")]
    private static extern uint NCryptEnumStorageProviders(
        out int providerCount,
        out IntPtr providerList,
        uint flags);

    [DllImport("ncrypt.dll")]
    private static extern uint NCryptFreeBuffer(IntPtr buffer);
    private static bool TbsReady()
    {
        IntPtr context = IntPtr.Zero;
        try
        {
            var parameters = new TbsContextParams2
            {
                Version = 2,
                Flags = 4
            };

            uint status = Tbsi_Context_Create(ref parameters, out context);
            return status == 0 && context != IntPtr.Zero;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (context != IntPtr.Zero)
                Tbsip_Context_Close(context);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TbsContextParams2
    {
        public uint Version;
        public uint Flags;
    }

    [DllImport("tbs.dll")]
    private static extern uint Tbsi_Context_Create(
        ref TbsContextParams2 contextParams,
        out IntPtr context);

    [DllImport("tbs.dll")]
    private static extern uint Tbsip_Context_Close(IntPtr context);
}
