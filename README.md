# I-Mortal trading app — security infrastructure

I-Mortal is building the security foundation for a trading application. The current
project is a .NET 10 TrustBroker covering confidential-compute authorization,
workload integrity, hardware-aware device identity, security sensors, protected
records, and replay/recovery designs. Production authorization and protected
provider operations remain disabled. A trading UI and exchange execution workflow
are not yet implemented.

**[Read the detailed project brief and architecture schematics](docs/project-brief.md)**

The brief includes system and startup diagrams, request-bound authorization and
attestation flows, device identity, a conceptual account schema, replay/crash
ordering, protected-state boundaries, sensor pipelines, protected-record access,
and the publication workflow. It distinguishes implemented code from designs and
missing production services.

Reviewed **2026-10-01**: 258 application/conformance C# files, two project definitions,
and 57 sanitized design templates. The public checks pass; their scope and the
remaining dependencies are documented in [inspection and validation](docs/security-infrastructure.md).

## Source map

| Directory | Contents |
| --- | --- |
| `security-infrastructure/src/Security/ConfidentialCompute` | TEE root gates, Intel TDX / AMD SEV-SNP evidence contracts, integrity, custody, recovery, protected-state interfaces, device identity and challenge algorithms |
| `security-infrastructure/src/Providers` | Windows/Linux TPM and Apple/Android provider boundaries; protected operations return denial |
| `security-infrastructure/src/Mobile` | Android/iOS evidence mapping and native probe contracts |
| `security-infrastructure/src/Security/Sensors` | Platform/user security reporting, inventory comparison and telemetry contracts |
| `security-infrastructure/src/Security/Provisioning` | Protected-record access, scoped receipts and restricted diagnostics |
| `security-infrastructure/src/Security` | Enrollment, identity derivation, production runtime and startup gates |
| `security-infrastructure/src/Tests` | Original conformance sources, sanitized; some require private deployment fixtures or Windows |
| `security-infrastructure/specification-templates` | Sanitized design contracts, for reading only; these are not valid deployment policies |
| `src/I-Mortal.Security` and `tests` | Existing standalone algorithm-policy and challenge-serialization library and regression suites |
| `tools` | Repeatable export, public-content validation and tests |

No key material, credentials, recovery address, recorded digest values, binaries,
private audit evidence or private Git history are included in the source snapshot.
Cryptographic APIs, algorithm names and code that computes hashes remain intact.
Removed values use explicit `PUBLIC_*_REMOVED` placeholders. Git itself necessarily
uses commit and object identifiers; the restriction applies to published file contents.
Earlier public commits are preserved; see [publication scope](docs/publication-scope.md).

## Verify

Requires Python 3.10+ and the .NET 10 SDK:

```sh
python3 tools/check.py
```

The check scans the reviewed file list, builds the public source, runs the existing
algorithm/serialization suites and checks publication-specific fail-closed behavior.
It does not provision hardware, generate production keys or authorize trading.
The original deployment-dependent test suite is included for inspection and future
adaptation, but is not represented as passing by this command.
See [inspection and validation](docs/security-infrastructure.md) for current limits.

## Update from the private working project

Run from this public repository, replacing the argument with the private project root:

```sh
python3 tools/export_security.py --source /path/to/private/TrustBroker
python3 tools/export_security.py --source /path/to/private/TrustBroker --check
python3 tools/check.py
```

The exporter reads only the paths in `tools/export-inputs.json`. Added or removed
C# or project files stop the export until that list is reviewed. Review new design
contracts explicitly as well. Changes to generated paths require a deliberate
update to `docs/publication-files.json`. The exporter never pushes automatically.
Review the diff, run the checks, then commit and push the public repository normally.
Never copy the private `.git`, build output or evidence directories into it.
CI repeats the public checks on pushes and pull requests; it cannot access the
private project or attest that future private changes have been exported.

No license grant has been selected. Public visibility alone does not grant an
open-source license.
