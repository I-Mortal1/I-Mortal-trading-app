# Inspection findings and validation boundaries

The workspace contains a .NET TrustBroker executable project, its conformance
project, security contracts, local experiments, audit evidence, compiled binaries
and an earlier public utility repository. The public export includes all current
application and conformance `.cs` / `.csproj` files. Backups are excluded.

## Architecture and implementation status

- `RootConfidentialComputeGate` evaluates origin, supported confidential-compute
  platform, boundary presence, attestation freshness, an injected attestation
  verifier and measurement policy. Intel TDX / AMD SEV-SNP verification dependencies
  include interfaces and evidence records; these do not implement a complete
  vendor attestation service by themselves.
- `IMortalSecurityUmbrellaRoot` composes confidential-compute, approved workload,
  user-runtime and developer-custody gates. Its caller must supply production
  authorization from a separately protected policy. Transaction-bound evaluation
  now shares one issuance across TEE, workload and developer checks, and requires
  lifecycle commit before approval; the default lifecycle denies all requests. Interfaces and descriptive
  evidence flags do not themselves establish that trusted provenance.
- `Program` retains its disabled production switch. `ProductionRuntimeGate`
  distinguishes contract verification from permission to operate. The sanitized
  embedded digest is deliberately invalid, and the deployment path is removed.
- Windows/Linux providers contain hardware detection code. Detection is not
  attestation. Enrollment, authorization, signing, attestation and revocation
  methods return disabled-operation results. macOS readiness is incomplete;
  mobile adapters depend on native evidence producers.
- Custody, USB/VeraCrypt, project integrity, protected-state durability/recovery,
  replay and user/device proof-of-possession code includes contracts, interfaces,
  predicates and serializers. The export preserves their current state; it does
  not invent storage engines, signature verifiers or trusted hardware producers.
- Test-only protected-operation seams model behavior with fakes. Passing those
  tests would not establish production crash consistency or hardware security.

## Current progress — 2026-09-30

The refreshed export adds 19 C# files and updates the existing authorization gates.
The working application source inventory is checked against the reviewed export
inputs; generated build files, backups and separate experiments are excluded.

| Area | Implemented in source | Remaining dependency / verification boundary |
| --- | --- | --- |
| Authorization foundation | Request-owned workload contexts, shared issuance, scoped intent, developer USB/recovery orchestration and commit-before-approval flow | Independently authenticated TEE evidence, durable issuance/replay authority, protected enrollment and real proof providers |
| Security sensors | Separate platform/user reporting, evidence freshness and scope checks, source inventory comparison, telemetry adapters, audit and notification interfaces | Real acquisition feeds, signed policy/manifest verification, durable incident storage and delivery providers |
| Protected records | Authorization-before-resolution, receipt scope/version/expiry checks, protected notification references and restricted diagnostic output | Provisioned record store, independent trust anchors, key operations and external service implementations |
| Trading application | Security telemetry contracts describe trading activity and withdrawal observations | No trading UI, exchange execution integration or end-to-end trading workflow is present in this snapshot |

These additions compile with the application. The public regression suites cover
publication behavior and the existing utility components; they do not establish
behavioral coverage of every new authorization, sensor or provisioning path.
Local experimental harnesses are outside the published test inventory.

## Verification commands

`python3 tools/check.py` validates the public file inventory and sensitive-value
patterns, checks the original utility copies against the full source snapshot,
runs algorithm-policy and byte-exact serialization regression suites, and runs
public export checks covering invalid trust anchors and disabled provider operations.
The full application is compiled as a dependency of the public export checks with
self-contained publishing and trimming disabled. This does not change the archived
application project definition.

Original conformance files are preserved for source completeness. They include
Windows-only expectations, private-policy pins, deployment paths, historical red
tests and an already-excluded earlier enrollment suite. They are not all portable,
and their successful execution is not claimed. The public checks do not exercise
real TPMs, Secure Enclaves, TDX/SNP hardware, production storage or trading.

## Maintaining the snapshot

`tools/export-inputs.json` is the reviewed input inventory.
`security-infrastructure/export-manifest.json` maps every input to an output and
records only how many values were redacted. `--check` regenerates in memory and
compares exact bytes, without writing source hashes into the repository.

Update the private implementation first, rerun the export, inspect the public diff
and execute the public checks. Newly introduced secrets must be removed or moved
out of source before publication. Never replace missing trust anchors with values
derived from the very data being authenticated, and never enable production merely
to make a public example run.

## Validation of this publication (2026-09-30)

The prepared snapshot contains 258 C# files, two project definitions and 57 design
templates. Export records show 208 digest redactions, zero identity redactions,
14 path redactions and 18 deployment-field redactions. Application and public
harness builds completed with zero warnings and errors.

The public checks passed: five exporter regression tests, 31 denial/verification
behavior checks, 17,972 algorithm input pairs, nine independent serialization
vectors and 11 rejection cases. Exact regeneration comparison also passed.
These counts describe this snapshot and should be refreshed after future changes.
