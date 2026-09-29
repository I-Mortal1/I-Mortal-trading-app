namespace IMortal.TrustBroker.Providers;

public static class TrustProviderFactory
{
    public static ITrustProvider Create()
    {
#if IMORTAL_WINDOWS
        return new Windows.WindowsTpmProvider();
#elif IMORTAL_LINUX
        return new Linux.LinuxTpmProvider();
#elif IMORTAL_MACOS
        return new MacOS.MacOsSecureEnclaveProvider();
#elif IMORTAL_IOS
        return new IOS.IosSecureEnclaveProvider();
#elif IMORTAL_ANDROID
        return new Android.AndroidKeystoreProvider();
#else
        throw new PlatformNotSupportedException(
            "No supported BYOTR hardware provider is available.");
#endif
    }
}
