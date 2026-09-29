# Publication scope

The first public snapshot includes six library source files: the algorithm
allowlist interface and implementation, plus the challenge data record, serializer
interface, canonical serialization contract and corrected serializer.

Supporting files are limited to build definitions, repeatable tests, public
documentation, a source-hash manifest and a narrow publication check. No original
repository history is imported; the initial commit contains this curated snapshot.

The source-hash manifest establishes byte identity for review. It is not a digital
signature or hardware-backed trust anchor. The publication check is a conservative
file allowlist plus heuristic credential scan, not proof that arbitrary future
changes contain no secrets. New file paths require an explicit manifest review.

Only public algorithm identifiers, protocol constants and synthetic test inputs
are included. This repository contains no configured accounts, private-key blobs,
tokens, production endpoints, machine-specific deployment paths or local evidence.

No open-source license has been selected in this publication. Public visibility
alone does not declare a license grant.
