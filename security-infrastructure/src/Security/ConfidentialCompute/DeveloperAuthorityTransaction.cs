namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public enum CanonicalUsbAvailability { Unknown = 0, Available = 1, Unavailable = 2 }

/// <summary>Untrusted observation until authenticated by the provisioned verifier.</summary>
public sealed record UsbAvailabilityObservation(
    IssuedAuthorization Issued, VeraCryptUsbKeyCustodyDescriptor Custody,
    CanonicalUsbAvailability State, string Revision, DateTimeOffset ObservedAt);

/// <summary>Fresh developer request shares the root's exact issuance and captured time.</summary>
public sealed class DeveloperAuthorityRequest
{
    internal DeveloperAuthorityRequest(IssuedAuthorization issued) { Issued = issued; }
    public IssuedAuthorization Issued { get; }
    public RootEvaluationRequest Root => Issued.Owner;
    /// <summary>Binding only; authentic verification remains mandatory.</summary>
    public DeveloperAuthorityContext CreateContext(ProtectedDeveloperIdentity identity,
        UsbAvailabilityObservation availability, DeveloperAuthorityProof proof) =>
        new(this, identity, availability, proof);
}

/// <summary>
/// Untrusted provider receipt. The verifier must authenticate the protected receipt,
/// not its reference/name. No address, key, password, or raw secret is carried here.
/// For recovery this references delivery/control verification of the enrolled email,
/// bound to identity/version, scope, issuance, request and expiry with bounded attempts.
/// </summary>
public sealed record DeveloperAuthorityProof(
    IssuedAuthorization Issued, DeveloperSourceAuthorityMode Mode,
    ProtectedDeveloperIdentity Identity, string Operation, DateTimeOffset VerifiedAt,
    string ProtectedReceiptReference);

public sealed class DeveloperAuthorityContext
{
    internal DeveloperAuthorityContext(DeveloperAuthorityRequest owner, ProtectedDeveloperIdentity identity,
        UsbAvailabilityObservation availability, DeveloperAuthorityProof proof)
    { Owner = owner; Identity = identity; Availability = availability; Proof = proof; }
    internal DeveloperAuthorityRequest Owner { get; }
    public IssuedAuthorization Issued => Owner.Issued;
    public ProtectedDeveloperIdentity Identity { get; }
    public UsbAvailabilityObservation Availability { get; }
    public DeveloperAuthorityProof Proof { get; }
    internal bool BelongsTo(DeveloperAuthorityRequest request) => ReferenceEquals(Owner, request);
}

/// <summary>Provisioned dependencies must not be taken from request payloads.</summary>
public interface IDeveloperAuthorityContextProducer
{
    bool TryProduce(DeveloperAuthorityRequest request, out DeveloperAuthorityContext? context);
}

public interface IProtectedDeveloperEnrollmentVerifier
{
    // Authenticate protected source, exact current authorized version, field AEAD,
    // keyed commitments and custody binding. Structural/public-hash integrity is insufficient.
    bool VerifyCurrent(IssuedAuthorization issued, ProtectedDeveloperIdentity identity);
}

public interface ICanonicalUsbAvailabilityVerifier
{
    // Unknown, access errors, and authentication failure are NOT unavailability.
    UsbAvailabilityObservation? Observe(IssuedAuthorization issued, VeraCryptUsbKeyCustodyDescriptor custody);
    bool VerifyCurrent(UsbAvailabilityObservation observation);
}

public interface IDeveloperModeProofProvider
{
    // Separate USB/recovery providers are provisioned into the orchestrator.
    // Must not export/reissue/replace mutation keys. Recovery must never enroll an email.
    // This foundation supplies no provider and performs no delivery/unlock operation.
    DeveloperAuthorityProof? Obtain(DeveloperAuthorityRequest request,
        ProtectedDeveloperIdentity identity, UsbAvailabilityObservation availability);
}

public interface IDeveloperModeProofVerifier
{
    // USB: independently authenticate physical backing source, exact USB, volume,
    // custody/key/key-object identity, and fresh enrolled-key possession for operation.
    // Recovery: independently authenticate protected preregistered email receipt,
    // issuance, identity/version/scope/nonce/expiry, bounded attempts and USB absence.
    // A public hash, address, label, serial, mount or reference is not verification.
    bool Verify(DeveloperAuthorityContext context);
}

/// <summary>Pure binding predicates, explicitly NOT proof of any producer's trust.</summary>
internal static class DeveloperAuthorityBindings
{
    internal static bool Match(DeveloperAuthorityContext c)
    {
        var issued = c.Issued; var r = issued.Owner; var i = r.Intent;
        var identity = c.Identity; var a = c.Availability; var p = c.Proof;
        var expected = i.DeveloperMode == DeveloperSourceAuthorityMode.NormalUsb
            ? CanonicalUsbAvailability.Available : CanonicalUsbAvailability.Unavailable;
        return i.Domain == UmbrellaSecurityDomain.DeveloperSourceCustody &&
            i.DeveloperMode is DeveloperSourceAuthorityMode.NormalUsb or DeveloperSourceAuthorityMode.UsbUnavailableEmailRecovery &&
            identity is not null && ReferenceEquals(identity, issued.DeveloperIdentity) &&
            identity.IdentityVersion == i.IdentityVersion &&
            a is not null && ReferenceEquals(a.Issued, issued) && ReferenceEquals(a.Custody, identity.RequiredUsbCustody) &&
            a.State == expected && !string.IsNullOrWhiteSpace(a.Revision) &&
            a.ObservedAt >= issued.Challenge.IssuedAt && a.ObservedAt <= r.EvaluationTime &&
            p is not null && ReferenceEquals(p.Issued, issued) && ReferenceEquals(p.Identity, identity) &&
            p.Mode == i.DeveloperMode && string.Equals(p.Operation, i.Operation, StringComparison.Ordinal) &&
            p.VerifiedAt >= issued.Challenge.IssuedAt && p.VerifiedAt <= r.EvaluationTime &&
            !string.IsNullOrWhiteSpace(p.ProtectedReceiptReference);
    }
}

/// <summary>
/// Orchestration only. Independent enrollment/availability/proof verification and
/// atomic lifecycle consumption are still required. No fallback between modes.
/// </summary>
public sealed class DeveloperAuthorityOrchestrator : IDeveloperAuthorityContextProducer, IDeveloperSourceAuthorityGate
{
    private readonly IProtectedDeveloperIdentityRecordValidator? _integrity;
    private readonly IProtectedDeveloperEnrollmentVerifier? _enrollment;
    private readonly ICanonicalUsbAvailabilityVerifier? _availability;
    private readonly IDeveloperModeProofProvider? _usb;
    private readonly IDeveloperModeProofProvider? _recovery;
    private readonly IDeveloperModeProofVerifier? _usbVerifier;
    private readonly IDeveloperModeProofVerifier? _recoveryVerifier;

    public DeveloperAuthorityOrchestrator(IProtectedDeveloperIdentityRecordValidator? integrity = null,
        IProtectedDeveloperEnrollmentVerifier? enrollment = null,
        ICanonicalUsbAvailabilityVerifier? availability = null,
        IDeveloperModeProofProvider? usb = null, IDeveloperModeProofVerifier? usbVerifier = null,
        IDeveloperModeProofProvider? recovery = null, IDeveloperModeProofVerifier? recoveryVerifier = null)
    { _integrity = integrity; _enrollment = enrollment; _availability = availability;
      _usb = usb; _recovery = recovery; _usbVerifier = usbVerifier; _recoveryVerifier = recoveryVerifier; }

    public bool IsSatisfied(DeveloperSourceAuthorityMode mode) => false;

    public bool TryProduce(DeveloperAuthorityRequest request, out DeveloperAuthorityContext? context)
    {
        context = null;
        try
        {
            var issued = request.Issued; var i = request.Root.Intent; var identity = issued.DeveloperIdentity;
            if (i.Domain != UmbrellaSecurityDomain.DeveloperSourceCustody || identity is null ||
                identity.IdentityVersion != i.IdentityVersion || _integrity?.Validate(identity) != true ||
                _enrollment?.VerifyCurrent(issued, identity) != true) return false;
            var state = i.DeveloperMode switch {
                DeveloperSourceAuthorityMode.NormalUsb => CanonicalUsbAvailability.Available,
                DeveloperSourceAuthorityMode.UsbUnavailableEmailRecovery => CanonicalUsbAvailability.Unavailable,
                _ => CanonicalUsbAvailability.Unknown };
            if (state == CanonicalUsbAvailability.Unknown) return false;
            var a = _availability?.Observe(issued, identity.RequiredUsbCustody);
            if (a is null || !ReferenceEquals(a.Issued, issued) || !ReferenceEquals(a.Custody, identity.RequiredUsbCustody) ||
                a.State != state || string.IsNullOrWhiteSpace(a.Revision) ||
                a.ObservedAt < issued.Challenge.IssuedAt || a.ObservedAt > request.Root.EvaluationTime ||
                _availability?.VerifyCurrent(a) != true) return false;
            var provider = state == CanonicalUsbAvailability.Available ? _usb : _recovery;
            var verifier = state == CanonicalUsbAvailability.Available ? _usbVerifier : _recoveryVerifier;
            if (provider is null || verifier is null) return false;
            // Never invoke a proof/delivery provider before identity and availability validation.
            var proof = provider?.Obtain(request, identity, a);
            if (proof is null) return false;
            var candidate = request.CreateContext(identity, a, proof);
            if (!DeveloperAuthorityBindings.Match(candidate)) return false;
            context = candidate; return true;
        }
        catch { return false; }
    }

    public bool IsSatisfied(DeveloperAuthorityContext context)
    {
        try
        {
            if (context is null || !DeveloperAuthorityBindings.Match(context) ||
                _integrity?.Validate(context.Identity) != true ||
                _enrollment?.VerifyCurrent(context.Issued, context.Identity) != true ||
                _availability?.VerifyCurrent(context.Availability) != true) return false;
            var verifier = context.Proof.Mode == DeveloperSourceAuthorityMode.NormalUsb ? _usbVerifier : _recoveryVerifier;
            return verifier?.Verify(context) == true;
        }
        catch { return false; }
    }
}
