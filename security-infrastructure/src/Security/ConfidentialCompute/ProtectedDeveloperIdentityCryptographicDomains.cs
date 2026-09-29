using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Authoritative domain-separation constants for protected developer
/// identity cryptography.
///
/// These constants contain no secret material and grant no authority.
/// </summary>
public static class ProtectedDeveloperIdentityCryptographicDomains
{
    public const string CompleteUsbIdentityEncryption =
        "i-mortal/developer-identity/complete-usb/v1";

    public const string UsbIdNumberEncryption =
        "i-mortal/developer-identity/usb-id-number/v1";

    public const string RecoveryEmailEncryption =
        "i-mortal/developer-identity/recovery-email/v1";

    public const string CompleteUsbIdentityCommitment =
        "i-mortal/developer-identity/commitment/complete-usb/v1";

    public const string UsbIdNumberCommitment =
        "i-mortal/developer-identity/commitment/usb-id-number/v1";

    public const string RecoveryEmailCommitment =
        "i-mortal/developer-identity/commitment/recovery-email/v1";

    public static string GetEncryptionDomain(
        ProtectedDeveloperIdentityField field)
    {
        return field switch
        {
            ProtectedDeveloperIdentityField.CompleteUsbIdentity =>
                CompleteUsbIdentityEncryption,

            ProtectedDeveloperIdentityField.UsbIdNumber =>
                UsbIdNumberEncryption,

            ProtectedDeveloperIdentityField.RecoveryEmail =>
                RecoveryEmailEncryption,

            _ => throw new ArgumentOutOfRangeException(
                nameof(field),
                field,
                "Unknown protected developer identity field.")
        };
    }

    public static string GetCommitmentDomain(
        ProtectedDeveloperIdentityField field)
    {
        return field switch
        {
            ProtectedDeveloperIdentityField.CompleteUsbIdentity =>
                CompleteUsbIdentityCommitment,

            ProtectedDeveloperIdentityField.UsbIdNumber =>
                UsbIdNumberCommitment,

            ProtectedDeveloperIdentityField.RecoveryEmail =>
                RecoveryEmailCommitment,

            _ => throw new ArgumentOutOfRangeException(
                nameof(field),
                field,
                "Unknown protected developer identity field.")
        };
    }
}