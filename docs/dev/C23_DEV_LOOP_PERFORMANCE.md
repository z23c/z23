# C23 development-loop performance ledger

This is the one performance authority for the live C23 developer loop. It
records measurements, not aspirations. The product contract remains
[`ZCODE_DEVELOPMENT_PRODUCT.md`](../work/ZCODE_DEVELOPMENT_PRODUCT.md); the runtime
and safety contract remains [`HOTSWAP.md`](./HOTSWAP.md).

The mission is simple: edit C23, let the resident owner classify and prove the
change, then read one concise result. Production remains one static,
reproducible, LTO-optimized binary. Consensus, reducer, storage, wallet,
transaction, network, supervisor and deployment authority never becomes
dynamically reloadable.

## Frozen benchmark v1

Command: `make dev-loop-history-bench`. The history window is permanently
anchored at `cdb0305a7a68544cdd26209e9074adaeda24a1a9`; later implementations
are compared against the same edit population. The generated, gitignored receipt is
`build/dev-loop/history-benchmark.json`; `make
dev-loop-history-bench-selftest` pins the boundary classifications.

At source head `cdb0305a7a68544cdd26209e9074adaeda24a1a9`, the benchmark walks
the latest 100 commits that each changed at least one production C translation
unit. It covers 259 edit occurrences in 158 current translation units, from
`b0d0f218ea5253a85a36686ae6ac0b557190491d` back through
`ee05b19a2b2dfdf0590d28800ecdf948d98b781d`; the frozen classified rows hash to
SHA-256 `e42c793d14b0e8f4eb3659592a291f5b1af83bb9d462e483790e5dcbfe6caa25`.

| Current class | Edit occurrences | Unique TUs |
|---|---:|---:|
| currently live-reloaded | 19 | 10 |
| eligible but unregistered | 3 | 2 |
| blocked by mutable file-scope state | 21 | 16 |
| blocked by direct global/state access | 61 | 31 |
| blocked by whole-node/host ABI assumptions | 35 | 21 |
| requires fast restart | 94 | 59 |
| forbidden dynamic authority | 26 | 19 |

The current narrow eligibility denominator is deliberately conservative:
existing live islands plus explicit pure codec/base/JSON/encoding/view/
condition roots that pass the static-state and direct-state scans. On that
denominator, weighted live-reload coverage is 19/22 = **86.36%**. Across all
non-forbidden production edits, 19/233 = **8.15%** currently reach the
resident live-feedback path. The largest measured miss is therefore fast
restart and component coverage—not the already-fast status example.

The representative replay set is derived, not handpicked: the 16 most frequent
non-forbidden current TUs, ordered by edit frequency then path. Its leading
members are the vault-intent controller, ZCODE task index, ZCODE work command
owners, Living Commons codecs/verifiers, build-fabric executor and current
wallet/metaverse read islands. The JSON receipt carries the exact full list and
classification of every occurrence.

## What the loop does

- **Profiles.** `DEV_LIVE`, `DEV_RESTART` and `INTEGRATION` contain no LTO;
  only `RELEASE` does (`make check-dev-loop-profiles`).
- **Exact artifact cache.** One verified host-local cache, keyed by the
  compiler capsule, base generation, normalized profile actions, ordered
  rewritten response and every input digest, serves miss, hit, edit-miss,
  revert-hit and second-worktree-hit; hits report 0 compiler and 0 linker
  processes. The canonical GCC capsule is byte-derived on first capture and
  reused within one process only while all nine resolved driver, backend,
  assembler, sysroot and ABI files are unchanged.
- **Resident restart candidate and affected proof.** Bounded non-consensus
  `.c` edits outside live islands relink the exact changed bytes into the
  existing fast-test graph and execute the complete canonical exact-group
  expansion cold. Candidate compile/link/probe and affected-proof
  compile/link/test run as parallel branches inside one before/after
  source-epoch guard. The resident runner opens the already verified
  dependency snapshot and supplies every changed translation unit explicitly.
  Focused proofs use the per-group cache and accept a cached result only when
  `groups_ran + groups_cached` equals the exact selected set.
- **Latest wins, prompt cancellation.** A newer save cancels the active epoch,
  preserves a debounced exact path batch, suppresses the stale verdict and
  reaps every process group in the bounded child session; watcher shutdown does
  not wait behind an active compiler, test or proof child. The recursive watcher
  discards traffic for the directories it refuses to enter.
- **Proof tiers and ownership.** Production behavior groups run on every save.
  The `make_lint_gates` policy/tooling self-test family and explicitly opt-in
  groups (event-log kill9 fuzz and throughput benchmark, Sapling-parameter
  shielded payment groups) are separate named integration groups. A file with an
  explicit shared impact rule is a terminal proof owner, so selection does not
  climb through a generic dispatcher into unrelated suites; the code-index and
  `native_code_command.c` owners keep `code_capsule`, and the all-command header
  keeps only generic registry/API/snapshot/hot-swap/platform proofs. An
  overwide reverse-caller union executes every exact group selected by the
  file's explicit path floor. Independent score/package contracts are separate
  exact groups under the `zcode_score_receipt` family, and real wall-clock
  command-latency assertions are a separate exclusive group.
- **Reflex stages.** An ordinary restart edit persists `EDIT_SEEN`,
  `IMPACT_READY` and a source-bound `reflex_ready` candidate receipt before
  affected tests; proof continues and emits a later `feedback_ready`. One warm
  watcher keeps a resident verified Merkle snapshot and publishes a bounded
  progressive event stream before ordered sealed-journal persistence. An
  unknown hot-swap dependency closure is discovered and verified inside one save
  (the discovery depfile binds an exact cache key), so first-save activation
  needs no second filesystem event.
- **Hot-swap islands.** Pure service islands (`zcode.c23.corpus.v1`,
  `zcode.c23.economics.v1`, the buyer-want view, the read-only metaverse
  agent service, and others) move validation, status calculation and rendering
  behind atomic versioned vtables while static handlers keep parsing,
  signatures, keys, clocks and storage. One debounce epoch may contain several
  `.c`/private-header paths only when every path resolves to the same closed
  island owner. Every fallback explanation is emitted as `why_not_live`.
- **Linking.** The development-linker preference is mold, lld, gold, then the
  platform default. `make dev-bin` prelinks the exact non-LTO dev and proof
  object generations once and records both regular files in the frozen restart
  plan, so a changed-object cycle links only the changed objects, and it builds
  a fixed non-LTO package verifier from the `DEV_RESTART` object epoch.
- **Source identity.** One native source-CAS capture derives a domain-separated
  resident-only SHA-256 identity/mutation record shared by the parallel
  branches, with exact total and re-read byte counts in the compact status. The
  Make-facing `source-identity.sh` derives its inventory, mutation and identity
  preimages through the `source-identity-batch` C23 helper, and the `t`,
  `t-fast` and `t-fast-exact` front doors pass the outer parse's
  `BUILD_SOURCE_RECORD`, `BUILD_COMPILER_ID` and `BUILD_SYSTEM_ID` to the
  recursive `$(MAKE)`.
- **Frozen replay.** `make dev-loop-history-replay` derives and replays the 14
  non-live paths of the 16-path representative set; every sample is
  verify-only, comment-only, watcher-stopped and byte-restored. Replay receipts
  report detection, identity, compile, link/reload, test, total time, process
  counts, bytes scanned, cache disposition and LTO/whole-node-link counts; any
  missing exact field makes the aggregate partial.
- **Landing proof.** A landing proof's compile dimension reuses the checkout's
  admitted `z23-dev`. The prefork bundle writes the warm-start donor marker, the
  donor survey admits a bundle-built generation's `build/bin` when no
  `build/obj` exists, and executed files are copied rather than linked, so an
  in-place rewrite cannot disturb a running donor. A missing donor falls back to
  the full cold build. The remaining critical path is the independent test
  dimension with lint beneath it; no gate is weakened. Release proof runs at
  the batch head while range-derived focused proof runs on every push; do not
  read a final-source verdict as release proof of every intermediate commit.

The single-island resident microbenchmark measured 227.280 ms p50 and 232.141
ms p95 on 20 distinct artifacts. That is evidence for one status island, not a
result for the frozen representative benchmark and not a coverage claim.

The existing non-LTO dev object graph relinks directly in 1.37 seconds and a
candidate `discover help` probe takes 0.05 seconds. Those measurements justify
the candidate path but not full process replacement: audited isolated regtest
readiness took 11.054 seconds cold and 11.204 seconds after a crash, while a
graceful stop did not drain within ten seconds. Full-node restart therefore
remains an integration tier rather than being mislabeled a sub-five-second
inner loop.

## Build profiles

- `DEV_LIVE`: one admitted module/island, affected immediate probe, no LTO.
- `DEV_RESTART`: affected cached objects plus an overlay/frozen-base link,
  isolated restart/probe, no LTO and no complete-graph save link.
- `INTEGRATION`: static non-LTO combined build and required test union.
- `RELEASE`: clean whole-program LTO and reproducibility proof.

`make check-dev-loop-profiles` is part of `watcher-safety-gates` and
`dev-loop-selftest`. The resident action-plan loader independently rejects
`-flto` and linker-plugin flags, so a stale or edited `flags.env` cannot
smuggle release work into a save cycle.

## Acceptance gate closure

| Gate | Evidence | Verdict |
|---|---|---|
| eligible live coverage at least 70% | frozen narrow denominator 19/22 = 86.36% | PASS |
| live p50 below 300 ms and p95 below 750 ms | 227.280 ms / 232.141 ms across 20 distinct status-island artifacts | PASS |
| trustworthy feedback at least 95% below five seconds | stable warm weighted replay 61/61 = 100%; static routing covers every non-forbidden class through live or restart | PASS |
| fast restart p95 below five seconds | stable warm p95 4.595 s | PASS |
| no LTO on edit, candidate, focused or ordinary commit | save receipts report zero LTO/Make/shell; ordinary pre-push uses non-LTO build/test profiles; release LTO remains opt-in | PASS |
| narrow saves perform no complete-graph link | changed-object receipts report zero complete-graph links | PASS |
| exact output and revert reuse | content-addressed artifact miss/hit/edit/revert/cross-worktree sequence | PASS |
| at least ten commits per release LTO | at least 12 commits between exact release proofs | PASS |
| static release remains reproducible | `make ci-reproducible` and `make repro-verify` byte-identity gates | PASS |
| dynamic authority boundary remains closed | consensus, reducer, storage, wallet, transaction, network, supervisor and deployment owners remain excluded and lint-enforced | PASS |

Measured focused-green capacity is 14.58x the repository-pinned old LTO-only
upper bound, above the required 10x target.

## Remaining non-blocking follow-ups

- Repeat the full changed-object latency population on an idle host. Stable
  warm feedback is complete at p50 4.047 s / p95 4.595 s and 61/61
  trustworthy under five seconds; the 9-path changed-object replay measured
  under load (p50 4.964 s / p95 6.656 s) and became partial when watcher waits
  exceeded the 10 s measurement bound. A cold first-watch safety read is
  56.7 MB and a steady-state one-TU read 31.6 KB. No proof is dropped or
  claimed green on timeout.
- The effective `dev-bin` recipe graph is now mechanically checked for LTO,
  including its package-verifier and adapter companions. Extend the same
  expanded-command proof to every integration/pre-push entry point; profile
  variable inspection alone is not sufficient evidence.
- Replace an isolated runtime only after that proof layer exists; the measured
  full-node launch is currently too slow for the five-second target.
- Extend the timed replay from the frozen representative weighted population to
  every non-forbidden historical TU. Static routing already covers those edits,
  but exhaustive timing would narrow the remaining sampling uncertainty.

No live service, canonical datadir, wallet, transaction, custody, deployment,
core or consensus path is part of this ledger or its benchmark.
