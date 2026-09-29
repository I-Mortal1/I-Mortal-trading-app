using IMortal.TrustBroker.Providers;
using IMortal.TrustBroker.Security;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

/// <summary>
/// Fail-closed ordinary-user platform cryptographic custody gate.
///
/// This gate evaluates an already-established UserSecurityProfile only.
///
/// The immutable developer/user authority separation is defined by
/// DeveloperUserCryptographicCustodyBoundary and is independently verified
/// before this implementation is installed or accepted.
///
/// This class deliberately does not branch directly on K2 compile-time
/// constants. Doing so would cause the C# compiler to eliminate branches and
/// produce CS0162 unreachable-code warnings. K2 remains an authoritative
/// architectural dependency, but its immutable constants are verified by the
/// installation/security continuity gate rather than re-evaluated as runtime
/// conditions.
///
/// No provider detection, key generation, key provisioning, key unwrap,
/// enrollment, authorization, attestation, signing, revocation, raw-key
/// access, developer USB access, source access, source mutation, TEE authority,
/// or production authority is performed here.
///
/// A true result means only that the supplied ordinary-user profile describes
/// an already-established hardware-ready, hardware-backed, non-exportable
/// custody state.
///
/// It is not a developer authorization decision and grants no authority.
/// </summary>
public sealed class UserPlatformCryptographicCustodyGate
    : IUserRuntimeSecurityGate
{
    private readonly UserSecurityProfile _profile;

    public UserPlatformCryptographicCustodyGate(
        UserSecurityProfile profile)
    {
        _profile = profile ??
            throw new ArgumentNullException(nameof(profile));
    }

    public bool IsSatisfied()
    {
        try
        {
            return Evaluate(_profile);
        }
        catch
        {
            // Security-sensitive evaluation is always fail-closed.
            return false;
        }
    }

    private static bool Evaluate(
        UserSecurityProfile profile)
    {
        if (string.IsNullOrWhiteSpace(profile.UserId))
            return false;

        if (string.IsNullOrWhiteSpace(profile.SecurityInstanceId))
            return false;

        if (profile.SecurityInstanceId.Length != 64)
            return false;

        if (string.IsNullOrWhiteSpace(profile.RegistrationNonceHash))
            return false;

        if (string.IsNullOrWhiteSpace(profile.SecurityPolicyVersion))
            return false;

        if (string.IsNullOrWhiteSpace(profile.SecurityPolicySha256))
            return false;

        if (profile.SecurityPolicySha256.Length != 64)
            return false;

        if (string.IsNullOrWhiteSpace(profile.ProviderId))
            return false;

        /*
         * HardwareReady is the minimum provider state accepted by this gate.
         *
         * ProductionAuthorized is intentionally rejected because production
         * authorization belongs to a different authority domain and must not
         * be interpreted by a user hardware-custody gate.
         */
        if (profile.TrustState < TrustProviderState.HardwareReady)
            return false;

        if (profile.TrustState >= TrustProviderState.ProductionAuthorized)
            return false;

        if (!profile.HardwareBacked)
            return false;

        if (!profile.NonExportableKeysSupported)
            return false;

        /*
         * The enrollment state must independently show hardware readiness.
         */
        if (profile.EnrollmentState < SecurityEnrollmentState.HardwareReady)
            return false;

        /*
         * Revocation always fails closed.
         */
        if (profile.EnrollmentState == SecurityEnrollmentState.Revoked)
            return false;

        /*
         * Production authorization is explicitly outside K3.
         */
        if (profile.EnrollmentState >=
            SecurityEnrollmentState.ProductionAuthorized)
        {
            return false;
        }

        if (profile.ProductionAuthorized)
            return false;

        return true;
    }
}