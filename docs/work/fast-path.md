# The Fast Path — our information algorithm for getting to correct C

Mantra: **code fearlessly; immutable history is the oracle.** ZClassic's
canonical history is not at risk from local experiments. Spend that advantage:
test against real historic blocks and throwaway datadir copies, rebuild derived
state instead of preserving bad local artifacts, and let real-chain canaries
answer consensus questions quickly. The hard line remains: never prove a repair
by mutating the live serving datadir first.

The C diff that fixes a problem is usually small — the **information
algorithm** is the work: turning a vague live symptom into the one correct
small change, with confidence, without expensive wrong turns. Each stage below
makes one failure class structurally impossible: misdiagnosing a coins-lag
symptom as a body gap, and shipping a chain-reset fix that deletes
`tip_finalize_log` rows without a reset-safe test.

## The stages (scale down for trivial changes — don't 9-agent a 3-line edit)

1. **GROUND in live truth — before any hypothesis.**
   `make diagnose-gap SLUG=<x>` dumps the three orthogonal views that must
   agree at tip — active public tip (A), best header tip (H), applied coins
   tip (C), and HAVE_DATA at A+1 (D) — plus the operational mode and active
   Conditions, and prints a root-cause verdict. STOP rule: **no hypothesis
   until the triple is captured.** This kills the bodies-vs-coins class:
   `C << A` is coins-application lag (reconcile), not a body gap; `A < H` with
   `D=true` is bodies-present-not-connected, not body-fetch.

2. **DESIGN + adversarially critique — before code.** For consensus-critical
   changes (anything touching `tip_finalize`, `*_log`, `coins_best`,
   `connect_block`, `active_chain_tip`, the boot reconcile span, or import /
   cold-import), write the design first and have it refuted. The load-bearing
   stamp: prove `can_reset_tip=false` and `weakens_gate=false`.

3. **RESET-SAFE UNIT TEST — before live.** Mirror
   `lib/test/src/test_stage_reducer_unwedge.c`: synthesize the broken state,
   assert the invariant the fix must hold (e.g. the public tip never drops
   below `coins_best`; no `*_log` rows deleted). Run it with
   `make t ONLY=<group>` (seconds).

4. **REPRODUCE ON A COPY — before touching the live chain.**
   `make repro-on-copy SLUG=<x> ARGS='...'` snapshots the live datadir to a
   throwaway copy and runs the node against it on an isolated port. It is a
   tip-regression detector: it FAILS LOUD if the public tip collapses — so the
   catastrophic tail (the 47,279 reset; the import-reset to ~199) is caught on
   a copy, never on the live node. For recovery work, make it a real H* climb
   gate too: `make repro-on-copy SLUG=<x> CLIMB_PAST=<height> ARGS='...'`
   FAILS if the copy only boots/holds flat and never serves a provable tip
   strictly above `<height>`. `-refold-from-anchor` proofs must use
   `REPRO_FULL=1` because the fold reads block bodies, and the harness now
   refuses that flag unless an anchor snapshot candidate is reachable at
   `$ZCL_MINT_ANCHOR_OUT` or `<src>/utxo-anchor.snapshot`. A refold proof also
   has to prove the boot loaded the SHA3-verified MINTED snapshot and has to
   observe H* at/below the gate before crossing it; starting above the gate is
   not a climb proof. The live datadir is never written.

5. **VERIFY + commit.** `make t ONLY=<group>` (inner loop) → `make build-only`
   / `make syntax-check` (does it compile) → `make lint` (full gates) → commit.

## The fast inner loop (use these, never `build/bin/test_zcl` in the loop)

| command | what |
|---|---|
| `make t ONLY=<group>` | run ONE test group from the exact strict candidate. Sources resolve under `build/test-rel-obj/epochs/<compile-epoch>/` (`-O3 -Werror -pedantic -DZCL_TESTING`, non-LTO); a mutation selects a fresh tree and compiler-cache hits recover unchanged TU work. `-MD -MP` depfiles close the old header false-green trap |
| `make t-fast ONLY=<group>` | hot-path ONE test group from the exact non-LTO, non-`-Werror`, `-O1` candidate under `build/bin/test-fast/epochs/<compile-epoch>/`; loosest/fastest loop |
| `make test_parallel_wpo` | rebuild the original whole-program LTO test binary at `build/bin/test_parallel_wpo` — only to debug a suspected per-TU-vs-LTO divergence |
| `make fast-changed-compile` | compatibility name for the source-wide dev compile proof; changed paths are classification hints only |
| `make fast-compile` | fastest no-link dev compile check; resolves every current source under `build/dev-obj/epochs/<compile-epoch>/`, with compiler-cache recovery |
| `make build-only` | strict release-flag incremental compile-check of the whole node (no link) |
| `make dev-bin` | incremental non-LTO node executable at `build/bin/z23-dev`; local AI/operator iteration only, not for release/deploy |
| `make agent-doctor` | no-build combined build/dev-lane/recent-test-failure status with one next safe command |
| `make agent-dev-status` / `z23 agentdevstatus` | no-build read-only dev-lane status: service, RPC/pre-RPC recovery, staged binary, saved deploy state, auto-reindex marker, deploy blocker/reason, stale-marker candidate, next action |
| `make agent-clear-stale-dev-reindex` | archive a proven-stale dev-lane `auto_reindex_request` after RPC height is at/above the marker anchor; no restart, no canonical/soak mutation |
| `make agent-stage-dev` | build and atomically stage `~/.local/bin/zclassic23-dev` for the next dev-lane restart without stopping the running service |
| `make syntax-check` | full no-link syntax check across every TU |
| `make lint-fast` | measured ~15 high-signal lint gates via the timed parallel driver (per-gate ms in `.cache/lint-timing/`; full `make lint` before commit) |
| `make agent-plan` | no-build JSON decision packet: changed-path/test classification hints, source-wide compile plan, fast-cache hit/miss, dev-lane stage/deploy commands, and native command shortcuts |
| `make agent-loop` | one-command agent loop: fast-ci checks by default; `ZCL_AGENT_LOOP_BIN=1` also links the dev binary; `ZCL_AGENT_LOOP_DEPLOY=dev` hot-swaps the dev lane |
| `make fast-ci` | cache-aware agent loop: `lint-fast` + exact source-wide compile/test proofs + native linger-service probe; identical green inputs skip repeated proven scope |
| `make immutable-history-canaries` | fast real-chain consensus KATs: h=478544 oversized canonical transaction plus consensus parity pins |
| `z23 status` / `z23 dumpstate <subsystem>` | native node reads (the native command registry is the sole agent interface) |
| `z23-dev status` | dev-lane native read against the installed dev binary |
| `make pre-push-ci` | bounded push gate: strict compile/lint plus mapped tests, reusing only exact skip-free content-addressed PASS receipts |
| `make install-quality-linger` | install background full-test, fuzz, and coverage user timers |
| `make quality-linger-status` | show latest background tests/fuzz/coverage JSON verdicts |
| `make test` | the fast fork-based parallel suite (~1 min), now built from the cached per-TU `test_parallel` (incremental after the first build); `make test-full` is the slow single-process binary |
| `make ci-reproducible` | build-twice byte-identity proof in isolated build dirs |

`make agent-plan` is the read-only preview of the loop: it emits
`zcl.agent_fast_plan.v1` with changed-file classification hints, mapped test
hints, the source-wide compile decision, green-input cache verdict, dev-lane stage/deploy
commands, and the no-build native command shortcuts. `make agent-doctor` embeds that same
plan alongside dev-lane health and recent focused-test failures.

`make immutable-history-canaries` is the fast consensus-risk lane for the
immutable ZClassic chain. It runs the pinned h=478544 125,811-byte transaction
fixture in `domain_consensus_tx_structural` and the golden
`consensus_parity` group. It is the first gate for bounded consensus predicate
changes; the heavier real-chain replay gates remain `make replay-canary-anchor`
and `make replay-canary-genesis`.

`make agent-loop` is the default edit-loop command for agents and operators. It
delegates to `make fast-ci` for the safe checks, then optionally links the
runnable dev binary with `ZCL_AGENT_LOOP_BIN=1`, stages the dev-lane binary
without restarting with `ZCL_AGENT_LOOP_DEPLOY=stage`, or hot-swaps the dev lane
with `ZCL_AGENT_LOOP_DEPLOY=dev`. `make fast-ci` remains the underlying cache-aware
gate and auto-selects `sccache cc` or `ccache cc` when present; override with
`ZCL_FAST_CC='ccache cc'`. Its automated proof runs the exact source-wide fast
test candidate under `build/bin/test-fast/epochs/<compile-epoch>/`; path-to-test
mappings are diagnostics and never reduce proof scope. The harness is cached
per-file, non-LTO, and compiler caches recover unchanged source work. It is
non-`-Werror`; compile warning enforcement stays in `make build-only`, strict
`make t`, and full CI. By default it uses `ZCL_FAST_COMPILE=changed`, a
compatibility spelling that runs the same source-wide `make fast-compile`
proof. Changed paths are classification hints only. Use
`ZCL_FAST_COMPILE=dev` for that same dev profile, or
`ZCL_FAST_COMPILE=strict` when you want `make build-only`; `make pre-push-ci`
sets that automatically. Provide mapped test hints with
`ZCL_FAST_TESTS=make_lint_gates,api` for routing diagnostics;
the automated proof remains source-wide. Use `ZCL_FAST_STRICT_TESTS=1` to pay
the strict exact-candidate proof. Set parallelism with `ZCL_FAST_JOBS=N`
(default caps at 16). Set
`ZCL_FAST_CHANGED_FILES_ONLY=1` when `ZCL_FAST_CHANGED_FILES[_FILE]` is already
the exact semantic input, as the pre-push hook does. Successful runs write a content
fingerprint under `.cache/zcl-agent-fast-ci/` covering changed-file contents,
selected test groups, compiler/cache choice, strict/live knobs, core scripts,
the Makefile, and the native probe binary mtime. A repeat with the same
fingerprint logs `fast result cache hit` and skips `lint-fast`, the selected
compile gate, and source-wide test proof; it still refreshes the live service probe unless
`ZCL_FAST_LIVE=0` is set. Disable this with `ZCL_FAST_CACHE=0`, reset it with
`ZCL_FAST_CACHE_RESET=1`, or move it with `ZCL_FAST_CACHE_DIR=...`. The live
check uses the C binary first (`build/bin/z23 agent` +
`build/bin/z23 healthcheck`) against the linger service; override the
binary with `ZCL_FAST_NODE_BIN=...` or skip the live check with
`ZCL_FAST_LIVE=0` for isolated/offline work. The shell gate trusts the native
`zcl.public_status.v3` status/serving/operator-needed contract rather than
re-encoding height-gap policy, and emits compact JSON summaries when a probe
fails. There is no external shell-wrapper fallback in the agent fast path; if
the native binary JSON interface is unavailable, rebuild
the binary or skip the live probe explicitly. Unmapped C/header/source-tree
changes fail closed until you either add a focused-test mapping or pass
`ZCL_FAST_TESTS=...`. The focused-test map is shared with native
`z23 agentimpact` in
`app/controllers/include/controllers/agent_impact_rules.def`; keep new mappings
there so the CLI and fast-CI shell lane do not drift.

Use `make dev-bin` when you need to run a changed node/agent CLI locally without
paying the release build's whole-program LTO pass. It emits
`make fast-rebuild` builds `build/bin/z23-dev` from cached per-file objects, with default
`ZCL_DEV_OPT=-Og`, hot consensus/crypto/script/validation buckets at
`ZCL_DEV_HOT_OPT=-O2`, no LTO, no strip, and optional fast-linker selection via
`ZCL_DEV_LINKER` (probes `mold`, then `ld.lld`, then `ld.gold`; expands to
**empty** when none is installed, so the link silently uses the platform
linker with no speedup. Verify with `command -v mold ld.lld ld.gold` before attributing
link time to it; set `ZCL_DEV_LINKER=` to force the platform default). When
`sccache` or `ccache` is
installed, the Makefile auto-wraps `CC` with it unless `ZCL_USE_CCACHE=0` is set. This is
the right binary for
local `agentbuild`, `agentimpact`, parser, API, and diagnostics iteration; it is
not a deploy or release artifact.

For an asynchronous edit-to-push path, start the existing resident verifier
with `z23-dev dev begin` and inspect its durable cycle with `z23 dev status`.
The watcher mints the same per-group content-addressed PASS receipts consumed by
`make pre-push-ci`. Pre-push still performs strict source-wide compilation and
lint, runs external-input or stale-graph groups fresh, rejects runtime SKIPs,
and requires `groups_ran + groups_cached` to equal the exact mapped set. A
documentation-only rebase therefore preserves unrelated C test receipts while
its documentation/lint authority continues to run fresh.

The native build contract is discoverable with `build/bin/z23 agentbuild`;
it advertises
`make agent-plan`, the stage-without-restart path, and the same native command
shortcuts.

Native commands are the agent interface. In the source tree, prefer
`build/bin/z23 status` and
`build/bin/z23 dumpstate supervisor` for fresh-code smoke checks, and
`build/bin/z23 discover help` to enumerate the command registry. Against
the dev lane use `build/bin/z23-dev status`. The native command registry
is the sole agent interface.
Do not add Python, shell, or helper-binary wrappers for new agent workflows.

Canonical operator APIs, in priority order:

1. `build/bin/z23 agentmap`, `agentlanes`, `agentliveness`, `agentimpact`,
   `agentbuild`, `agent`, `healthcheck`, and raw RPC methods — native C binary
   client to the running linger service.
2. REST (`/api/v1/agent`, `/api/v1/openapi`) — public web/API surface.

`make agent-loop` is the normal AI/operator edit gate. Before pushing `main`, the
tracked pre-push hook computes the exact `origin/main..HEAD` changed-file set,
passes it to `make pre-push-ci`, and rejects remote refs other than
`refs/heads/main`. `make pre-push-ci` runs cached focused fast-ci for that file
set (`build-only` plus mapped `t-fast` groups); it does not rerun the full suite
on every push, and it forces `ZCL_FAST_LIVE=0` so a live node condition remains
telemetry rather than a push blocker. Set `ZCL_FAST_STRICT_TESTS=1` for a
deliberate strict focused run. Full `make ci` still exists for release-grade manual runs, but the
expensive proof lanes are kept fresh by `zclassic23-test-suite.timer`,
`zclassic23-fuzz.timer`, and `zclassic23-coverage.timer`. Install them with
`make install-quality-linger`; inspect their latest
`zcl.background_quality_status.v1` verdict with `make quality-linger-status`.

## Invariants that hold across every stage

- **Live truth before design.** Pull `make diagnose-gap` first; never reason
  from a guessed cause.
- **Reproduce on a copy before any live chain/datadir mutation.** No exceptions
  for consensus-critical experiments.
- **Never weaken a consensus gate; never delete `tip_finalize_log` rows; never
  lower the public tip below `coins_best`.** Recovery only ever raises or holds
  the tip.
