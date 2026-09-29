namespace IMortal.TrustBroker.Providers;

public sealed record TrustDetectionResult(
    TrustProviderState State,
    string ProviderId,
    bool HardwareBacked,
    bool NonExportableKeysSupported);
