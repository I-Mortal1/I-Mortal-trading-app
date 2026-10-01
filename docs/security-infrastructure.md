# Inspection findings and validation boundaries

**Reviewed 2026-10-01. Production operations remain disabled.**

The detailed current description is the [project brief and architecture schematics](project-brief.md).
It covers the common security infrastructure and ordinary-user path with explicit
implementation status, source references, data flows, and remaining dependencies.

## Current progress — 2026-10-01

The current source snapshot contains 258 C# files: 239 runtime files and 19 original
conformance files, plus two project definitions and 57 sanitized design templates.
Runtime source contains 15,621 lines including comments and blank lines. These
counts exclude generated files, backups, independent probes, and binaries.

The authorization foundation shares one issuance across TEE and workload checks,
checks request ownership, and requires lifecycle commit before approval. Its legacy
evaluation overload always denies, and the default lifecycle denies issuance and
commit. Production evidence services and durable lifecycle infrastructure remain
missing. Program.Main does not instantiate the authorization root.

The source also implements separate platform/user sensor orchestration, source
inventory comparison, asset-movement correlation, protected notification reference
resolution, and protected-record receipt checks. Real acquisition, independent
monitoring, durable incident storage, delivery, and record/key providers remain
external dependencies. There is no trading UI or exchange execution integration.

The protected-operation test seam currently returns predetermined fault-point
results, retains restart state in memory, and leaves reconciliation as a stub.
It does not establish production persistence or crash recovery.

## Current progress — 2026-09-30

This heading is retained for earlier incoming links. The current review and
[implementation matrix](project-brief.md#project-inventory-and-implementation-status)
supersede the earlier summary. Historical observations must be evaluated against
the source version they actually inspected.

## Verification commands

```sh
python3 tools/check.py
python3 tools/export_security.py --source /path/to/private/TrustBroker --check
```

The first command checks the publication allowlist and sensitive-value patterns,
checks the six utility copies against exported source, builds portable harnesses
and the application dependency, and runs selected regression checks. The second
requires the private workspace and compares exact regenerated export bytes.

## Validation of this publication — 2026-10-01

- Exact regeneration: PASS, 318 generated source/project/template/manifest files.
- Exporter regression tests: PASS, 5 tests.
- Public export behavior: PASS, 31 checks.
- Algorithm policy: PASS, 17,972 input pairs across four cultures.
- Challenge serialization: PASS, 9 independent vectors and 11 rejection cases.
- Public compilation and release checks: PASS.

These results establish only the behaviors tested. The original MSTest suite was
inspected but was not represented as fully passing: it includes deployment-bound
fixtures, Windows assumptions, removed private values, excluded enrollment tests,
and unfinished/red tests. The portable harness builds disable self-contained
publishing, trimming, and single-file output; they do not test a trimmed release.
No native hardware, live authentication, production storage, or trading workflow
was exercised. Historical probe baseline mismatches remain separate unresolved
lineage evidence; baseline expectations were not silently replaced.

## Maintaining the snapshot

`tools/export-inputs.json` is the reviewed source inventory.
`security-infrastructure/export-manifest.json` maps inputs to outputs and records
redaction counts. `docs/publication-files.json` covers all reviewed public files,
including documentation. The exporter compares source/template bytes; it does
not independently verify prose claims or make missing infrastructure operational.

Update the implementation, deliberately review inventory changes, regenerate the
export, update the brief to match the source, review the diff, and run the checks.
New secrets must be removed before publication. Public-content scanning is a
heuristic, not proof that arbitrary new content is safe to publish. Sanitized
specification templates are documentation and cannot serve as authenticated
production policies. See [publication scope](publication-scope.md).
