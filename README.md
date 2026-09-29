# I-Mortal trading app

This repository contains completed, tested security utility components for the
I-Mortal trading app project. This first publication is a .NET 10 library, not a
finished trading application. It contains no trading engine, exchange connector,
order execution, account authentication or production authorization service.

## Components

| Function | Location | Implemented behavior |
| --- | --- | --- |
| Algorithm policy | `src/I-Mortal.Security/AlgorithmPolicy` | Accepts only the exact `ECDSA-P256-SHA256-P1363` / `EC-P256` pair using ordinal, case-sensitive comparisons |
| Challenge serialization | `src/I-Mortal.Security/Challenges` | Produces deterministic, domain-separated, length-prefixed challenge bytes using strict UTF-8, NFC input, big-endian integers and millisecond wire timestamps |
| Algorithm regression checks | `tests/AlgorithmPolicy` | Exact acceptance, aliases, malformed values, character mutations, culture independence and repeated calls |
| Serialization regression checks | `tests/Challenges` and `tools/check.py` | Independent byte-exact vectors, overflow, Unicode and size rejection cases |

The original namespace is retained for source continuity. The folder structure
groups the published code by its function.

## Build and verify

Install the .NET 10 SDK and Python 3, then run:

```sh
python3 tools/check.py
```

The projects have no third-party package dependencies. `NuGet.Config` clears
remote package sources, so restore uses locally installed framework packs.
The check builds both test executables and runs the two regression suites.

## Behavior boundaries

Algorithm acceptance does not verify a signature. Serialized bytes do not prove
freshness, authentication or authorization. The challenge data API accepts Unix
seconds; the serializer writes checked Unix milliseconds. Inputs must already be
NFC-normalized. The serializer uses the canonical-serialization contract's domain.

The earlier seconds/domain encoding is not supported by this published version.
No migration or compatibility claim is made for old signed challenge bytes.
The tests do not establish hardware security, attestation or production readiness.

This publication excludes unfinished validator drafts, synthetic composition
models, deployment policies, hardware probes, account data, local audit reports,
credentials and compiled artifacts. No private keys are required to build or test.

## Updates

Keep updates scoped to the two published components until another component has
been reviewed and tested. Run `python3 tools/check.py` and review every staged
file before pushing. `docs/source-manifest.json` records the reviewed source bytes;
update it deliberately with reviewed source changes. See [publication scope](docs/publication-scope.md).
