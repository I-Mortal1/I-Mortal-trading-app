# Publication scope and redaction policy

This publication expands the initial six-file utility library to the entire current
TrustBroker C# source tree and both project definitions. The input manifest lists
all reviewed source paths. It also includes selected security design contracts as
`.conf.example` documentation. The export manifest records paths and redaction
counts, never original values or content digests.

Only the public export changes. Private source, deployment contracts, hardware,
key stores and authorization controls are not modified.

## Excluded material

- Key blobs (public or private), certificates, credentials and recorded digests.
- Recovery contact identity, machine paths, configured key names and TPM inventory.
- Binaries, debug symbols, package caches, checksum sidecars and generated files.
- Hardware observations, audit reports, state/evidence snapshots and private history.
- Backups, invalid/intermediate contract drafts and local probe/experimental harnesses.
- The two root deployment policies, which are access-restricted in the inspected
  workspace. Their contents were not readable and are not part of this export.

Local probe drafts are separate experiments, not linked into the application.
The active IDE report describes an isolated allowlist harness; it is not a full
application build, hardware attestation or signature-verification result.

## Transformations

Line endings are normalized to LF. Recorded hexadecimal digests become
`PUBLIC_DIGEST_REMOVED`. Recovery addresses, deployment paths, configured key
names and observed deployment fields receive descriptive non-secret placeholders.
Algorithms, security logic and denial switches are retained. No replacement trust
anchor is calculated from candidate policy bytes, and no check is bypassed to make
a sanitized policy pass. Templates cannot be used as authenticated policies.
Original tests that depended on removed constants retain placeholders and need
new, reviewed synthetic fixtures before they can be used as portable tests.

The original public utility manifest contained source digests. They have been
removed from the current tree; earlier public commits still contain those public
source digests. Existing history is preserved. Rewriting Git history would also
not erase existing clones or caches. No claim is made that Git object identifiers
or historical public source digests cease to exist.

## Review boundary

The content checks reject recorded digest literals, common credential formats,
key/certificate blocks and long encoded blobs. They enforce a reviewed file list,
reject symlinks, and verify the original utility files against their exported
counterparts by direct byte comparison. These checks are heuristics, not a proof
that arbitrary future content is free of secrets. Review every diff before upload,
especially new string literals, identifiers, byte arrays and configuration fields.
