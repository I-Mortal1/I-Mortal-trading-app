namespace IMortal.TrustBroker.Security.Provisioning;

public enum SecurityDiagnosticCode { DependencyUnavailable, AuthorizationDenied, InvalidRecord, AuditFailure, DeliveryUnavailable }

/// <summary>Allowlisted structured diagnostics. No exception, payload, identity or arbitrary message field.</summary>
public sealed class SafeSecurityDiagnostic
{
    public SafeSecurityDiagnostic(Guid correlation, SecurityDiagnosticCode code)
    { Correlation = correlation; Code = Enum.IsDefined(code) ? code : SecurityDiagnosticCode.InvalidRecord; }
    public Guid Correlation { get; }
    public SecurityDiagnosticCode Code { get; }
    public override string ToString() => $"security_event={Code};correlation={Correlation:D}";
}

public static class ProtectedOutputReference
{
    // Format restriction prevents accidental payload/address/exception reflection.
    // It is NOT authentication; independent scoped verification is still mandatory.
    public static bool IsValid(string? value) => value is { Length: 36 } &&
        Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty;
}
