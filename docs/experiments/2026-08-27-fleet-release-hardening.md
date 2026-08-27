# Fleet release hardening

Copyright 2026 Rhett Creighton – Apache License 2.0

## Intent

Qualify one C23 release for four public nodes without weakening validation,
custody, or rollback boundaries. The release must recover an equal-height
competing-header fork through ordinary authenticated body download, refuse
ambiguous software-commons proofs and seals, and reject zero-value swap
contracts before persistence.

## Measured fleet condition

At `2026-08-27T08:04:14Z`, nodes 1, 2, and 4 independently reported verified
height 3,230,654. Node 3 reported height 3,230,421 while its peers advertised
height 3,230,654. Node 3 had accepted the canonical header sequence but lacked
the earliest body on the competing branch. Its existing recovery condition had
exhausted three attempts because it required the best header to be strictly
higher than the active tip and selected only the tip height.

The repaired scheduler permits an equal-height best-header branch, walks back
to the common ancestor, and queues the earliest missing body by the exact
best-chain hash. This changes download scheduling only. Header validity,
proof-of-work, chain-work selection, block validation, and activation remain
under their existing authorities.

## Release boundary repairs

- A root Merkle proof is canonical only when it is a directory proof with an
  empty path, zero levels, and zero children. The direct verifier and encoder
  now reject the same malformed root arena.
- Core sealing opens every repository-relative component with `O_NOFOLLOW`,
  hashes only regular files, and requires stable device, inode, size, mtime,
  and ctime before and after the read. Writer limits match reader limits.
  Duplicate or nonfinal roots, embedded NUL, truncated physical lines, and
  read failures are fatal parser errors.
- Positive swap amounts that convert below one zatoshi are refused. The output
  parameter remains untouched on every refusal, and all previously valid
  truncation and upper-bound behavior remains unchanged.
- Changes to the Merkle verifier now select `code_merkle_proof` in the native
  impact plan, preventing future focused gates from omitting its proof KAT.
- Snapshot installation gives both SQLite opens the retained reserved-file
  descriptor and verifies that the operator-facing datadir path still names
  the pinned directory before returning it. A concurrent rename cannot
  redirect backup creation or verification to a replacement inode.
- Binary-slot launch remains descriptor-bound. Platforms without a supported
  descriptor execution primitive refuse launch instead of accepting a
  path-replacement race. Generic macOS builds no longer enable host-specific
  instructions unless the operator explicitly requests a native build.
- The hot-swap confinement audit now tracks the exact development preprocessor
  frame across nested host conditionals. Its self-test proves that loading in
  the release branch is still detected.
- Peer inventory membership uses bounded probes, refreshes duplicate slots,
  and discards incomplete indexes after allocation failure. Exact linear
  fallback preserves membership without an unbounded mutex-held probe.
- New software wants bind issuance to within 300 seconds of the node clock and
  expiry to 30 days from both issuance and node time. A caller-controlled
  future stamp cannot create a decades-open advertisement.

## Evidence

Observed at `2026-08-27T08:48:07Z` (`2026-08-27T04:48:07-04:00`) on an AMD
Ryzen 7 PRO 8840U with GCC 16.1.1:

```text
release-focused exact set   PASS  35/35 groups; groups_failed=0; self_skips=0
core_seal exact             PASS  groups_failed=0; self_skips=0
impact_composition exact    PASS  groups_failed=0; self_skips=0
vault_read exact            PASS  groups_failed=0; self_skips=0
core-seal-check             PASS  70 files; 23 sections
core-seal-root-mirror       PASS
hotswap-module-imports      PASS  8 modules; no undeclared imports
file-size ceiling           PASS  39 application baselines unchanged
git diff --check            PASS
full lint                   PASS  156/157 before size repair
incoming focused exact set  PASS  23/23 groups; groups_failed=0; self_skips=0
hot-swap confinement        PASS
hot-swap static state       PASS  38 translation units
package registry            PASS  217 sources; one host sandbox selected
SIMD divergence self-test   PASS
remote ship transaction     PASS
inventory/time focused set  PASS  12/12 groups; groups_failed=0; self_skips=0
final lint                   PASS  157/157 gates
final cold registered suite PASS  966/966 eligible groups; groups_failed=0
```

The one lint refusal was `swap_controller.c` growing from its 1,053-line
ratchet to 1,080 lines because of a test-only wrapper. The wrapper was removed,
the production converter remained directly tested, the file returned to 1,053
lines, and the exact size gate passed without raising a threshold.

The incoming focused set was observed at `2026-08-27T09:51:32Z`
(`2026-08-27T05:51:32-04:00`) on the same host and compiler. Linux exercised
the snapshot installer and descriptor-bound launcher. macOS behavior remains
fail-closed but is not claimed as runtime-qualified without a macOS host.

The final lint and cold registered suite completed at `2026-08-27T11:00:49Z`
(`2026-08-27T07:00:49-04:00`). The canonical runner gated nine
parameter-file-heavy groups and reported 20 explicit stress/live-fixture skip
markers; every eligible group passed without an unobserved environment.

## Fleet acceptance and live-path repair

At `2026-08-27T12:47:00Z` (`2026-08-27T08:47:00-04:00`), all four canonical
services were active, reported `synced=yes`, and held the same immutable daemon
bytes (`sha256:eb59b4ae7948739f1259e103f81cb8a82b4d0654c478c82498c638ef8e22d0f2`).
The processes reported source identity
`6b7f7106db1f2d75db685bf4085c315494c24955ff6d2bc89cc23481183be0da`
and build commit `1db9879fb3c003887592cd9f667c9a6affa0db4a`. Nodes 1--3
independently reported active height 3,230,860 and exact tip hash
`00000a6e04cc073ea91705110cbed8520b0cc6a0d70ee6fd1d3c2db7e97cb22e`.
Node 4 subsequently advanced through height 3,230,868 and announced verified
height 3,230,869.

Node 4's schema migration was preceded by a clean offline copy of its
5,154,942,976-byte `node.db`. Source and copy both hashed to
`dc80570815a0683057e31af5b30105c3e3d1fef596227c12444aee1453cb4f69`.
The migrated process opened schema v75. Its receipt-less 942,141,440-byte
projection required a real SQLite quick check on rotational storage; the check
completed in 965,565 ms without a timeout or rollback.

Live qualification exposed a separate background-validation lifetime defect.
The boot adapter resolved the network datadir into a stack buffer, while the
long-lived validation service retained that borrowed pointer. Stack reuse made
body reads attempt `/blocks/...` or a corrupted-prefix path. The service now
owns a bounded copy, refuses empty or oversized paths before starting, and a
regression clobbers the caller buffer after initialization. Focused acceptance
passed for `bg_validation_reverify` (1/1), `have_data_unreadable` (1/1), and
the integrity selection (6/6), with zero failures or skips.

Review of the concurrent main advance found two fail-open edge cases before
the next release. Shop board count queries now treat every non-row SQLite step
as an error instead of publishing a false zero total. Market review commits
atomically compare the token-bound prior state in the update predicate, so a
concurrent local mark wins and the stale plan is refused. Injected
`SQLITE_INTERRUPT` and deterministic interleaving tests cover both cases.
The same non-row audit was applied to the subsequently merged name-record
totals: text and address counts now return `-1` on an interrupted store step,
with both refusal paths pinned by deterministic tests.

Wallet policy remained unchanged and no custody operation or canonical
database surgery was performed.
