using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public interface ISecurityClock
{
    DateTimeOffset UtcNow { get; }
}