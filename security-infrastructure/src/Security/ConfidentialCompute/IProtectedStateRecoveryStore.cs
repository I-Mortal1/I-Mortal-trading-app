using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface IProtectedStateRecoveryStore
{
    ProtectedStateRecoveryRecord? ReadRecoveryRecord(
        Guid transactionId);
}