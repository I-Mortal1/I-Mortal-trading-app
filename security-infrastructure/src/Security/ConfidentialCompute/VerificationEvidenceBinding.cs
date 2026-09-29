using System;

namespace IMortal.TrustBroker.Security.ConfidentialCompute;

public sealed class VerificationEvidenceBinding
{
    private readonly byte[] _subjectDigest;

    internal VerificationEvidenceBinding(
        string verificationPurpose,
        byte[] subjectDigest,
        ConfidentialSecurityBoundaryIdentity boundaryIdentity)
    {
        if (string.IsNullOrWhiteSpace(verificationPurpose))
        {
            throw new ArgumentException(
                "Verification purpose is required.",
                nameof(verificationPurpose));
        }

        if (subjectDigest is null)
        {
            throw new ArgumentNullException(nameof(subjectDigest));
        }

        if (subjectDigest.Length == 0)
        {
            throw new ArgumentException(
                "Subject digest must not be empty.",
                nameof(subjectDigest));
        }

        BoundaryIdentity = boundaryIdentity
            ?? throw new ArgumentNullException(nameof(boundaryIdentity));

        VerificationPurpose = verificationPurpose;
        _subjectDigest = (byte[])subjectDigest.Clone();
    }

    public string VerificationPurpose { get; }

    public byte[] SubjectDigest =>
        (byte[])_subjectDigest.Clone();

    public ConfidentialSecurityBoundaryIdentity BoundaryIdentity { get; }
}
