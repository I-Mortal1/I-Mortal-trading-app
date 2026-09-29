using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

internal sealed class ConfidentialProtectedStateDurabilityVerifier
{
    public bool Verify(
        bool transactionDataDurable,
        bool protectedStateDurable,
        bool replayStateDurable,
        bool recoveryRecordDurable,
        bool commitMarkerValid)
    {
        return
            transactionDataDurable &&
            protectedStateDurable &&
            replayStateDurable &&
            recoveryRecordDurable &&
            commitMarkerValid;
    }
}
