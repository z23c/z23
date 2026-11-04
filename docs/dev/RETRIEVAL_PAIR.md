<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Paired retrieval observation

<!-- claim: symbol-present dev.retrieval.pair engine/composition/commands/retrieval_pair.def # CAS-backed observational command -->
<!-- claim: symbol-present zcode_retrieval_science_result_compose cognition/services/src/zcode_retrieval_science_adapter_service.c # maintained measurement adapter -->
<!-- claim: symbol-present zcl_native_retrieval_pair_load tools/command/native_dev_retrieval_pair_input.c # artifact decoder -->

The dev command `dev retrieval pair` computes both profile arms from one
declared frozen baseline. It calls the existing retrieval science adapter;
it does not accept supplied scores, comparison verdicts or result objects.

```sh
build/bin/z23-dev dev retrieval pair --input='{"workspace":"<CAS-workspace>","artifact_root":"<SHA3-256-of-exact-artifact-bytes>"}'
```

The artifact is stored in the existing workspace object store. Its address is
the untagged SHA3-256 of its complete JSON bytes. The command uses a bounded
raw read and independently verifies that address before parsing. The maximum
artifact size is 128 KiB. Missing, corrupt, oversized or ambiguous input is
a command failure; no partial measurement is returned.

The artifact is a JSON object with exactly these 25 fields:

| Fields | Value |
| --- | --- |
| `schema` | `zcl.retrieval_pair_artifact.v1` |
| `parent_profile_hex`, `child_profile_hex` | Existing canonical retrieval profile wires, lowercase hex |
| `parent_heuristic_hex`, `child_heuristic_hex` | Existing canonical heuristic wires |
| `policy_hex` | Existing comparison policy v2 wire |
| `study_hex`, `task_hex`, `candidate_hex` | Existing canonical science study, task and candidate wires |
| `environment_policy_hex`, `hardware_profile_hex` | Existing canonical environment policy and hardware profile wires |
| `task_id`, `query` | Nonempty task identity and query bound by the paired workload |
| `source_root`, `retrieval_projection_root` | Lowercase hex roots for the declared logical source and projection |
| `baseline` | Ordered array of objects containing exactly `path` and nonnegative integer `context_bytes` |
| `ranking_complete` | Boolean declaring whether the baseline covers the complete ranking |
| `relevant_paths` | Reviewed gold path array |
| `action_sequence`, `result_sequence`, `challenge_block_height` | Nonnegative JSON integers |
| `challenge_block_hash` | Lowercase hex root |
| `started_unix`, `finished_unix`, `now_unix` | Nonnegative JSON integers |

Integer transport is bounded by INT64_MAX. Wire parsers and existing services
apply their narrower limits. Duplicate keys, decoded NUL, malformed UTF-8,
trailing non-whitespace and unknown fields are refused. The extractor observes
context bytes only; profiles requiring other features cannot obtain a complete
measurement by treating missing features as zero.

The command derives the context-byte feature snapshot, uses the acyclic v2
workload, and lets the existing services check lineage and all artifact joins.
In particular the observation v1 source and snapshot source must match.

Output includes parent/child evaluation wires and roots, snapshot and heuristic
roots, paired-input/workload identities, observation wire/root, action root and
science result wire/root. The comparison and result statuses remain separate:
an OBSERVED, NEGATIVE_RESULT or NULL_RESULT observation can each be a successfully
computed command result. A command success alone is not a quality verdict.
Each arm also exposes its metric availability flags and integer basis-point
metrics. Its exact context-byte total is a decimal string so the full uint64
range is preserved without a floating-point or signed-integer conversion.

Retain the input artifact bytes and their address, the exact executable/source
identity, and the complete command reply for another operator to recompute.
The command does not store or sign the returned evidence. Source provenance
and run facts remain declared; chronology and holdout independence remain
unverified, reproduction is not run, and promotion is not authorized. Independent
execution and a reproduction attestation are subsequent evidence, not inferred
from opaque roots or the command's exit status.
