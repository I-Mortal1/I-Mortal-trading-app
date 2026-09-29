using System.Security.Cryptography;
using IMortal.TrustBroker.Providers;
using IMortal.TrustBroker.Registration;

namespace IMortal.TrustBroker.Security;

public sealed class SecurityEnrollmentService
{
    private readonly ITrustProvider _provider;
    private readonly SecurityPolicyReference _policy;

    public SecurityEnrollmentService(
        ITrustProvider provider,
        SecurityPolicyReference policy)
    {
        _provider = provider ??
            throw new ArgumentNullException(nameof(provider));

        _policy = policy ??
            throw new ArgumentNullException(nameof(policy));
    }

    public UserSecurityProfile Register(
        UserRegistrationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        ValidateRequest(request);

        var registrationNonce =
            Convert.ToHexString(
                RandomNumberGenerator.GetBytes(32))
            .ToLowerInvariant();

        var nonceHash =
            SecurityIdentityDeriver.HashNonce(
                registrationNonce);

        var securityInstanceId =
            SecurityIdentityDeriver.DeriveSecurityInstanceId(
                request.UserId,
                registrationNonce);

        var detection = _provider.Detect();

        var enrollmentState =
            detection.State switch
            {
                TrustProviderState.HardwareReady =>
                    SecurityEnrollmentState.HardwareReady,

                TrustProviderState.HardwareDetected =>
                    SecurityEnrollmentState.ProviderDetected,

                TrustProviderState.ProviderAvailable =>
                    SecurityEnrollmentState.ProviderDetected,

                _ =>
                    SecurityEnrollmentState.RegistrationAccepted
            };

        var profile = new UserSecurityProfile(
            UserId: request.UserId,
            SecurityInstanceId: securityInstanceId,
            RegistrationNonceHash: nonceHash,
            SecurityPolicyVersion: _policy.Version,
            SecurityPolicySha256: _policy.Sha256,
            ProviderId: detection.ProviderId,
            TrustState: detection.State,
            HardwareBacked: detection.HardwareBacked,
            NonExportableKeysSupported:
                detection.NonExportableKeysSupported,
            EnrollmentState: enrollmentState,
            ProductionAuthorized: false);

        SecurityEnrollmentInvariants.AssertSafe(profile);

        return profile;
    }

    private static void ValidateRequest(
        UserRegistrationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.UserId))
            throw new ArgumentException(
                "UserId is required.",
                nameof(request));

        if (request.UserId.Length > 256)
            throw new ArgumentException(
                "UserId exceeds the maximum length.",
                nameof(request));
    }
}
