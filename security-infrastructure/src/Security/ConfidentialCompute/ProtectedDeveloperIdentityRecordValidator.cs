using System;
using System.Security.Cryptography;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Fail-closed structural and cryptographic integrity validator for
/// ProtectedDeveloperIdentity.
///
/// Validation establishes protected-record integrity only.
///
/// Successful validation does not grant source-mutation authority,
/// developer source authority, production authorization, trading authority,
/// provider-dispatch authority, signing authority, key-unwrapping authority,
/// identity-enrollment authority, identity-rotation authority, plaintext
/// identity recovery authority, user-runtime authority, or I-Mortal Security
/// Umbrella root authority.
///
/// This implementation does not decrypt protected identity fields, unwrap
/// keys, access VeraCrypt key material, perform external I/O, enroll or rotate
/// identities, register itself, or mutate the supplied identity.
/// </summary>
public sealed class ProtectedDeveloperIdentityRecordValidator :
    IProtectedDeveloperIdentityRecordValidator
{
    private const int CryptographicDigestLength = 32;

    private readonly IProtectedDeveloperIdentityIntegrityDigestCalculator
        _integrityDigestCalculator;

    public ProtectedDeveloperIdentityRecordValidator(
        IProtectedDeveloperIdentityIntegrityDigestCalculator
            integrityDigestCalculator)
    {
        _integrityDigestCalculator =
            integrityDigestCalculator ??
            throw new ArgumentNullException(
                nameof(integrityDigestCalculator));
    }

    public bool Validate(
        ProtectedDeveloperIdentity identity)
    {
        if (identity is null)
        {
            return false;
        }

        byte[]? completeUsbIdentityCommitment = null;
        byte[]? usbIdNumberCommitment = null;
        byte[]? recoveryEmailCommitment = null;
        byte[]? previousIdentityRecordDigest = null;
        byte[]? storedIntegrityDigest = null;
        byte[]? calculatedIntegrityDigest = null;

        try
        {
            if (identity.IdentityVersion <= 0)
            {
                return false;
            }

            if (identity.CompleteUsbIdentityEnvelope is null ||
                identity.UsbIdNumberEnvelope is null ||
                identity.RecoveryEmailEnvelope is null ||
                identity.RequiredUsbCustody is null)
            {
                return false;
            }

            completeUsbIdentityCommitment =
                identity.CompleteUsbIdentityCommitment;

            usbIdNumberCommitment =
                identity.UsbIdNumberCommitment;

            recoveryEmailCommitment =
                identity.RecoveryEmailCommitment;

            previousIdentityRecordDigest =
                identity.PreviousIdentityRecordDigest;

            storedIntegrityDigest =
                identity.IdentityRecordIntegrityDigest;

            if (!IsRequiredDigest(
                    completeUsbIdentityCommitment) ||
                !IsRequiredDigest(
                    usbIdNumberCommitment) ||
                !IsRequiredDigest(
                    recoveryEmailCommitment) ||
                !IsRequiredDigest(
                    storedIntegrityDigest))
            {
                return false;
            }

            if (!IsPreviousRecordDigestValid(
                    identity.IdentityVersion,
                    previousIdentityRecordDigest))
            {
                return false;
            }

            calculatedIntegrityDigest =
                _integrityDigestCalculator.Calculate(
                    identity);

            if (!IsRequiredDigest(
                    calculatedIntegrityDigest))
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(
                storedIntegrityDigest,
                calculatedIntegrityDigest);
        }
        catch
        {
            return false;
        }
        finally
        {
            Zero(
                completeUsbIdentityCommitment);

            Zero(
                usbIdNumberCommitment);

            Zero(
                recoveryEmailCommitment);

            Zero(
                previousIdentityRecordDigest);

            Zero(
                storedIntegrityDigest);

            Zero(
                calculatedIntegrityDigest);
        }
    }

    private static bool IsRequiredDigest(
        byte[]? value)
    {
        return value is not null &&
               value.Length == CryptographicDigestLength;
    }

    private static bool IsPreviousRecordDigestValid(
        long identityVersion,
        byte[]? value)
    {
        if (identityVersion <= 0 ||
            value is null)
        {
            return false;
        }

        if (identityVersion == 1)
        {
            return value.Length == 0;
        }

        return value.Length == CryptographicDigestLength;
    }

    private static void Zero(
        byte[]? value)
    {
        if (value is not null &&
            value.Length > 0)
        {
            CryptographicOperations.ZeroMemory(
                value);
        }
    }
}