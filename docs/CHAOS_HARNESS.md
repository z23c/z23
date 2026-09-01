# Chaos Harness

Two chaos tools, for two layers:

| Tool | Layer | What it kills | Make target |
|------|-------|---------------|-------------|
| `zclassic23-chaos` | **Simulation engine** | Nothing real — a deterministic in-process state machine driven by `.scenario` files | `make chaos` |
| `crash_recovery_test` | **Real process (C7)** | A real `build/bin/z23` binary, via `SIGKILL` to its process group | `make test-crash` / `make test-crash-bootstrap` |

Use the **full-binary kill-9 harness** to prove on-disk recovery of a real
node under `SIGKILL`; use the **sim engine** for fast, hermetic,
seed-reproducible consensus/boot scenarios.

---

## Full-binary kill-9 (C7)

`crash_recovery_test` (`tools/crash_recovery_test.c`) spawns a **real**
`build/bin/z23`, drives it briefly, `SIGKILL`s its whole process
group, restarts it, and asserts the recovery invariants. It is the
end-to-end counterpart to the in-process unit test
`tests/harness/src/test_kill9_recovery.c`.

### Isolation contract (the hard rails)

The single audited chokepoint is **`tools/scripts/isolated_node_env.sh`**,
sourced by `make test-crash-bootstrap` and `make soak-ci`. It guarantees
a spawned test node can never touch the live node, datadir, or ports:

- **Throwaway datadir** under `/tmp` (`mktemp -d /tmp/zcl23-<kind>-XXXXXX`);
  refuses if the path resolves under `~/.zclassic-c23*`.
- **39xxx port quad** (`-port/-rpcport/-fsport/-httpsport` = base+0..3,
  default base 39030 (quad 39030/39031/39032/39033)) plus a dead `-connect=127.0.0.1:39999` sink.
  Refuses if any chosen port is in the live refuse-set
  (`8023 8033 8034 … 18034 18232 …`).
- **ss(8) LISTEN preflight** — the *authoritative* collision guard:
  refuses loudly if any chosen port is already `LISTEN`ing (an operator
  port-math error). The trap is armed *before* this check so a refusal
  never leaks the just-minted datadir.
- **`-connect=39999`** is load-bearing isolation: it sets
  `g_connect_only`, which both skips seeds and bypasses the
  auto-addnode-to-`127.0.0.1:8034` path that would otherwise dial
  `zclassicd`.
- **`-fsport` override** is required — without it the node binds the
  hardcoded live file-service port `18034`.
- **Process-group kill**: the node is spawned under `setsid` (its own
  group); teardown sends `SIGTERM` then `SIGKILL` to the whole group,
  with a `pkill -f -- -datadir=$ISO_DD` backstop that can only ever
  match the throwaway datadir string.
- **Cleanup trap** on `EXIT/INT/TERM` kills the group and `rm -rf`s the
  `/tmp` datadir (only after re-proving it is under `/tmp`).

### Bootstrap-regtest self-seed

`make test-crash-bootstrap` runs the harness with **no external
fixture**: it mints an isolated `/tmp` regtest datadir, spawns the node,
mines `--seed-blocks` blocks via `generate`, then runs the kill/restart
loop.

> **Build caveat:** the regtest `generate` RPC does not solve Equihash, so
> the seed stays at genesis. On a genesis/short seed the harness prints a
> loud `KNOWN BLOCKED (owner-gated reducer boot-init)` witness and refuses
> to run the (vacuous) kill/restart loop, returning 0 by default (HARD FAIL
> with `ZCL_CRASH_REQUIRE_TEETH=1`).

### Recovery assertions

Reused from the unit invariants, so the full-binary harness asserts the
same shape the in-process SQLite slice proves:

- **Height monotone** — `getblockcount` never regresses across a
  kill/restart (`CR_HEIGHT_REGRESSED`).
- **UTXO count monotone / commitment identical-or-advanced**
  (`CR_UTXOS_DECREASED`, `CR_COMMITMENT_CHANGED_BUT_NOT_ADVANCED`).
- **Zero UTXO above tip** (`CR_UTXO_ABOVE_TIP`) — reads the spawned
  node's **`node.db`** directly, read-only:
  `SELECT COUNT(*) FROM utxos WHERE height > tip` (tip from
  `node_state.coins_best_block → blocks.height`), the exact invariant from
  `test_kill9_recovery.c:p11_7_count_utxos_above_tip`. There is **no
  `coins.db`** — the canonical UTXO set lives in `node.db`.
- **Recovered within budget** — `getblockcount` answers ≥ pre-kill
  height within the 60 s restart wait.

### Operational variant (NOT in default CI)

MVP #7's literal "caught up to **peer**-tip within 2 min" needs a second
node. A `--with-peer` two-node resync variant (spawn a 2nd isolated
regtest node, mine on B, kill A, assert A resyncs to B's tip within 120 s)
is **PLANNED — not yet implemented** (no such flag exists in
`crash_recovery_test.c` today); regtest two-node P2P sync is
timing-sensitive, so it would ship opt-in/operational and **not** in
`make ci` or the default self-test. See `docs/RUNBOOK.md`.

---

## Simulation chaos engine (`zclassic23-chaos`)

`zclassic23-chaos` runs declarative scenarios. Each non-comment line is one
command, arguments are whitespace-separated, and assertions use simple integer
comparisons.

Run every checked-in scenario:

```bash
make chaos
```

Run the fast deterministic simulator gate:

```bash
make sim-fast
```

`sim-fast` is the default inner-loop harness when a change touches reducers,
boot liveness, peer selection, fault injection, or scenario semantics. It runs
the `chaos_harness` unit slice, every checked-in `.scenario`, and a bounded
seed sweep of the seed-sensitive peer-churn scenario. Override the sweep size
when needed:

```bash
make sim-fast CHAOS_SEEDS=256
```

Run one scenario with command-level progress:

```bash
make zclassic23-chaos
build/bin/zclassic23-chaos --scenario=tools/sim/scenarios/peer_churn.scenario --verbose
```

The checked-in corpus includes `partition_recovery_c3.scenario`, a deterministic
C3-shaped replay where block traffic at the operator-bundle seed frontier is
dropped during a virtual partition and accepted after the partition expires.
Use it as the small simulator repro for "body transfer paused, then resumed"
before escalating to the full `make mvp-coldstart-to-tip-local` wall-clock proof.

Replay a scenario under a specific seed:

```bash
build/bin/zclassic23-chaos --scenario=tools/sim/scenarios/seeded_peer_churn.scenario --seed=0x2a --verbose
```

Failed standalone runs write a summary and a copy of the scenario into
`chaos-output/`. Use `--artifact-dir=PATH` to redirect those files.

## Scenario Format

Comments start with `#`. Blank lines are ignored. A minimal scenario looks like:

```text
seed        0x0000000000000001
boot_phase  idb_complete
peer_count  0
advance_clock +60s

expect      no_crash
expect      consensus_rejects == 0
```

Keep scenarios short and deterministic. Prefer explicit seeds and concrete
assertions over broad smoke checks.

## Commands

`seed HEX`
: Sets the scenario seed. Hex and decimal values are accepted.
  The CLI `--seed=HEX` override supersedes the scenario's embedded `seed`
  line, so a failing seed-sweep run can be replayed without editing the
  checked-in scenario.

`boot_phase idb_complete|listening|mempool_open`
: Selects the simulated boot phase reached before injected events run.

`peer_count N`
: Creates `N` in-process simulated peers.

`at_event HEIGHT COMMAND [ARGS...]`
: Records a scheduled event and dispatches the nested command immediately.
  This gives scenarios the same shape as future height-driven replay while the
  current harness remains single-pass.

`kill_peer ID`
: Disconnects a configured simulated peer.

`random_kill_peers count=N`
: Uses the scenario seed to choose `N` connected peers and disconnect them.
  The selected peers are deterministic for a given seed.

`send_block peer=I file=PATH [height=N]`
: Reads a non-empty fixture file from a connected peer, records the simulated
  send, and advances `tip_height`. When `height=N` is present, `tip_height`
  moves to that height if it is higher than the current tip. Full consensus
  validation is future work. Checked-in block fixtures live under
  `tests/fixtures/blocks/`.

`send_malformed_block peer=I type=ENUM`
: Simulates a bad block from a connected peer and increments
  `consensus_rejects`. Valid types are `invalid_pow`, `bad_merkle`,
  `bad_timestamp`, `bad_size`, `bad_coinbase`, `duplicate_tx`, `bad_bits`, and
  `bad_nonce`.

`advance_clock +DURATION`
: Moves the virtual platform clock forward. Durations use `s`, `m`, `h`, or
  `d`, for example `+30s` or `+1h`.

`trigger_oom_at LABEL`
: Arms the one-shot safe allocation fault hook and verifies the next allocation
  at `LABEL` fails.

`partition_network for=DURATION`
: Arms the network partition hook until the virtual wall clock passes the
  duration. Peer block traffic during the window is counted as
  `partition_drops` and is not delivered to the simulated node.

`auto_reindex_request anchor=N`
: Writes the durable auto-reindex marker through the production
  `boot_auto_reindex_request()` primitive and updates the auto-reindex metrics.
  Repeated lower anchors fold the marker down to the minimum anchor while
  incrementing the bounded attempt count.

`auto_reindex_clear_if_covered coins_best=N`
: Models the stale-marker cleanup gate used during boot: a positive,
  nonterminal marker clears only when `coins_best` is strictly greater than the
  marker anchor. Equality intentionally leaves the marker pending.

`auto_reindex_mark_terminal anchor=N`
: Rewrites the marker as terminal (`count=-1`). Terminal markers are
  present-but-not-pending and are not cleared by the stale-marker cleanup gate.

`expect no_crash`
: Asserts that the scenario did not mark itself crashed.

`expect METRIC OP VALUE`
: Compares a metric with `==`, `!=`, `>=`, `<=`, `>`, or `<`. Current metrics:
  `tip_height`, `reorg_count`, `consensus_rejects`, `mempool_prune_runs`,
  `mempool_prunes`, `active_peers`, `killed_peers`, `blocks_sent`,
  `malformed_blocks`, `block_bytes`, `clock_advance_count`,
  `clock_advance_seconds`, `scheduled_events`, `alloc_faults`,
  `graceful_shutdowns`, `partition_drops`, `sim_time`,
  `auto_reindex_anchor`, `auto_reindex_count`, `auto_reindex_pending`,
  `auto_reindex_terminal`, `auto_reindex_requests`, and
  `auto_reindex_clears`. In `mode simnet` (below), two more metrics are
  available: `simnet_converged` and `simnet_tip_monotonic`.

## Simnet mode: driving a REAL cluster

Every command above is bookkeeping-only: `sim_peer` counts blocks and bytes
but never calls into consensus. `mode simnet` switches a scenario into a
different engine that drives an actual `engine/modules/sim/simnet_cluster` — real
`connect_block`/`disconnect_block`, real nChainWork fork-choice, real
Sapling-ready coins views. Use it when a scenario needs to prove something
about *consensus behavior* (a reorg really disconnects and reconnects, a
partitioned peer really diverges and really re-converges), not just about
the harness's own counters.

`mode simnet` must be the first simnet-related line in the file (a
scenario cannot mix legacy `peer_count`/`send_block`/etc with simnet mode).
Commands:

`mode simnet`
: Switches the scenario into simnet mode. No other simnet_* command is
  valid before this line.

`simnet_nodes N [honest=<permille>]`
: Creates an N-node cluster (2..128) seeded with the scenario's `seed`.
  Must run exactly once, after `seed` and `mode simnet`. Optional
  `honest=<permille>` (0..1000; default 1000 = all honest) marks a fraction
  of nodes byzantine: a byzantine node forges INVALID blocks that honest
  peers reject on delivery. Node 0 is always honest. Roles are drawn from a
  sub-stream disjoint from the scenario RNG, so `honest=1000` (or omitting it)
  is byte-identical to the pre-role harness.

`simnet_mint node=I`
: Mints one block on node `I`'s own local view. Mining is independent per
  node until relayed — build competing branches by minting on different
  nodes before relaying either.

`simnet_relay node=I`
: Broadcasts every block node `I` has minted but not yet relayed to every
  peer NOT currently partitioned from `I`.

`simnet_deliver`
: Drains the deterministic delivery queue (real accept/connect on each
  receiving node) and records each node's tip height for the monotonicity
  check below.

`simnet_partition a=I b=J`
: Severs the `I<->J` link. Relays from `I` no longer reach `J` (and vice
  versa) until healed.

`simnet_heal a=I b=J`
: Restores the `I<->J` link and resyncs both directions — every block `I`
  has ever minted, targeted at `J` only (and vice versa), so a peer that
  missed relays sent to OTHERS while partitioned still catches all the way
  up. Follow with `simnet_deliver` to actually process the resync.

### Invariants

At the end of every simnet-mode run, regardless of what the scenario wrote
as `expect` assertions, the harness:

1. Drains any still-pending deliveries (`simnet_deliver` is idempotent, so
   this is a no-op if the scenario already drained explicitly).
2. Checks **cluster convergence**: every node's tip hash AND coins-view
   digest must be identical.
3. Checks **per-node tip monotonicity**: no node's tip height may have
   regressed between any two `simnet_deliver`/end-of-run observations.

On either violation the harness prints `SIMNET REPRO SEED=0x<hex>` (the
scenario's seed) to stdout and exits nonzero — the same one-liner shape as
`wire_sweep`'s `FAIL seed=0x...`, so a failing simnet scenario is
replayable the same way: rerun with `--seed=0x<hex> --verbose`. A scenario
can also assert the same two things explicitly and earlier, mid-run, via
`expect simnet_converged == 1` / `expect simnet_tip_monotonic == 1`.

Checked-in fixtures: `tools/sim/scenarios/simnet_partition_heal.scenario`
(sever then heal a link, prove the isolated peer catches all the way up)
and `tools/sim/scenarios/simnet_competing_reorg.scenario` (two isolated
branches of different work, relayed and delivered together, prove the
loser really reorgs via real `disconnect_block`/`connect_block`). Both run
as part of `make chaos` like every other scenario. The in-process
regression test lives in `test_chaos_harness` (`tests/harness/src/test_chaos_harness.c`),
including a deliberately-unconverged scenario proving the invariant check
fires instead of silently reporting PASS.

Because `mode simnet` links the real consensus/coins/script/validation
stack, `zclassic23-chaos` is now built the same whole-program-LTO way as
`wire_sweep`/`test_parallel` (`$(ALL_SRCS)`), not a hand-picked file list —
expect a longer first build, same as any other `ALL_SRCS`-linked tool.

## Recording a full-state trace

`mode simnet`'s `expect` metrics (`simnet_converged`, `simnet_tip_monotonic`,
...) are a small, fixed set of hand-picked counters. When a scenario fails or
behaves surprisingly, that is often not enough to see what actually
happened — you cannot ask "what did node 3's chain/coins state look like
right before it diverged" from the counters alone. A full-state trace closes
that gap: an opt-in, append-only NDJSON file that snapshots every simulated
node's chain/coins facts after each `simnet_mint`, `simnet_deliver`,
`simnet_partition`, and `simnet_heal`.

Enable it with `--trace-dir=PATH` (every scenario the process runs) or the
`trace_dir PATH` scenario command (this scenario only). Neither is required
by anything — a scenario that never mentions tracing, and `make chaos`
by default, write no trace file and behave exactly as before this existed.

```bash
build/bin/zclassic23-chaos --scenario=tools/sim/scenarios/simnet_partition_heal.scenario \
    --trace-dir=/tmp/zcl-trace
```

writes `/tmp/zcl-trace/simnet_trace.jsonl`, one JSON object per line, one
line per (node, event). Each line carries `seq` (the harness's own
monotonically increasing event counter — shared by every node's line for the
same event), `event` (the command name that triggered the snapshot),
`node_id`, and three nested objects: `chain` (`tip_height`, `tip_hash`),
`coins` (`commitment_hex`, `utxo_count` — the XOR-accumulator UTXO
commitment, see `core/modules/coins/include/coins/utxo_commitment.h`), and `cluster`
(`delivery_fingerprint`, `byzantine_rejected` — cluster-wide, so identical
across one event's lines).

Query a trace after a run with `simnet_trace_query` (`tools/sim/
simnet_trace_query.c`, `make tools/sim/simnet_trace_query`), a standalone
linear-scan filter that links only `platform/modules/json` — no DB, no node libs, no
simulator code, same discipline as `tools/postmortem_to_scenario.c`:

```bash
build/bin/simnet_trace_query --file=/tmp/zcl-trace/simnet_trace.jsonl \
    --node=2 --event=simnet_partition
```

Filters (`--node=`, `--event=`, `--seq=`) combine with AND; omitting all of
them prints every line. A match-count summary always goes to stderr so it
never pollutes piped stdout.

**Why this isn't "reuse the live diagnostics dumpers":** every
`<name>_dump_state_json()` registered in `engine/controllers/include/
controllers/diagnostics_dumpers.def` reads ONE live process's global
singleton state (or a SQLite table on the live node's `node.db`) — none
take an explicit state instance as a parameter, because a real node has
exactly one of everything. `simnet_cluster` (`engine/modules/sim/include/sim/
simnet_cluster.h`) is a pure in-memory, N-instance simulator: each node owns
its own `struct coins_view_cache` and retained block set and never touches
the live process's globals, so there is no existing per-instance dumper to
call. `engine/modules/sim/include/sim/simnet_trace.h` instead reuses, byte-for-byte,
the public `simnet_cluster` accessors already exposed for exactly this kind
of inspection (`simnet_cluster_tip_hash`/`_tip_height`/`_coins_digest`/
`_delivery_fingerprint`/`_byzantine_rejected`) and the same `platform/modules/json`
library the diagnostics registry itself uses to serialize.

## Cost assertions live next door, not in a scenario

The scenario DSL asserts CORRECTNESS metrics. Cost assertions — "did this code
path get algorithmically slower?" — live in `make sim-perf`
(`tools/sim/simperf.c`), which reuses this file's `expect METRIC OP VALUE`
grammar verbatim on the command line but runs its own multi-size workload ladder
instead of a single-pass scenario. `make chaos` stays machine-independent as a
result. See [`SIMNET_PERF.md`](./SIMNET_PERF.md), including why a `.scenario`
command was the rejected alternative.

## Adding Fault Injection

Add the production hook first, defaulting to inactive and cheap on the hot path.
Then add a narrow chaos command that arms the hook and proves it fired. Keep
the command deterministic, update `test_chaos_harness`, and add a scenario only
after the command has focused unit coverage.

Existing examples:

- Allocation faults: `platform/modules/base/src/safe_alloc.c` plus `trigger_oom_at`.
- Network partitions: `core/modules/net/src/net_fault.c` plus `partition_network`.

## From Capsule To Scenario

When a postmortem capsule exposes a replayable failure, convert it into the
smallest scenario that preserves the causal shape. Steps 1-2 are automated by
`tools/postmortem_to_scenario.c`; steps 3-5 stay manual.

1. **[automated]** Use the capsule's recorded tape state as the scenario
   `seed`.
2. **[automated, best-effort]** Map the boot state to `boot_phase`, when
   derivable from the capsule's `log.txt`.
3. **[manual]** Convert peer disconnects, clock movement, malformed inputs,
   OOM labels, and network stalls into chaos commands.
4. **[manual]** Add the assertion that would have caught the bug, usually
   `expect no_crash` plus a specific metric.
5. **[manual]** Check in the scenario as a permanent regression.

Run the automated half of the conversion:

```bash
make postmortem-to-scenario CAP=<capsule-dir> [OUT=<path>]
```

`CAP` is an **unpacked** `.cap` directory (`tape.bin` + `manifest.json` +
`log.txt` + ...) as written by `postmortem_capture_write()` — a live
capsule directory listed by `z23 ops postmortem list`, or one built by hand for
testing. `OUT` defaults to `tools/sim/scenarios/repro_<seed_hex>.scenario`.
The tool (also runnable directly as `build/bin/postmortem_to_scenario
--cap=DIR [--out=PATH]`) writes a `.scenario` file that:

- Sets `seed 0x<hex>` from the tape's recorded state and `boot_phase` (derived
  from a `[boot-stage]` trace line in `log.txt` when present, else defaulted
  to `idb_complete` and marked `UNDETECTED`).
- Documents crash signal, crash time, reason, capsule path, and the tape's
  event counts (rng draws, clock advances, injected events) in a comment
  header.
- Lists the capsule's injected-event log in order (type + payload length,
  walked read-only via `seed_tape_next_event`), bounded to the first 200
  events with an overflow note beyond that, plus a category summary by event
  type.
- Emits a `# TODO (manual steps 3-5)` block pointing at the event list above
  and a placeholder `expect no_crash` so the file **parses** immediately —
  it is not yet a regression test.

**Honest scope**: a postmortem capsule records ONE node's RNG stream, clock,
and injected-event log. A `.scenario` (especially `mode simnet`) can describe
an N-node cluster. Reconstructing a full multi-node scenario from a
single-node capsule is lossy by construction, so the tool's output is a
labeled starting point for the manual steps below, not a proven repro. The
emitted `seed` line is the tape's informational xoshiro register snapshot,
not the original scalar seed — it will not reproduce the capsule's exact RNG
stream in a fresh run (see the generated file's own comment, and
`docs/examples/09_seed_replay.c` for the exact-replay path via
`postmortem_capsule_load_tape()` / `z23 ops postmortem replay`).

## Reproducing a failure

Two one-command targets turn a failing seed (from a nightly
`wire_sweep` run) or a saved capsule back into a live, deterministic
repro. Both reuse the existing `wire_sweep` binary (`tools/sim/
wire_sweep.c`) and its own `--start`/`--count` seed selection — no new
harness, no new binary:

```bash
# Replay one exact failing seed printed by `make wire-sweep`
# ("FAIL seed=0x..."):
make simnet-repro SEED=0x2a

# Replay every seed_0x*.tape capsule saved under a directory (or a
# single .tape file) by a prior `make wire-sweep` failure:
make simnet-replay CAP=build/wire-sweep-output
```

`simnet-repro` runs `wire_sweep --start=SEED --count=1 --verbose` — the
single-seed slice of the same sweep loop `make wire-sweep` drives.
`simnet-replay` (`tools/scripts/simnet_replay_capsule.sh`) recovers the
seed from each capsule's `seed_0x<HEX>.tape` filename and calls
`wire_sweep` the same way. It does not need to load the `.tape` file's
contents: `wire_sweep_run_one(seed)` is a pure function of the scalar
seed, so the saved capsule and a bare `--start=<seed>` replay always
reproduce the identical adversary archetype, sub-case, and event
stream. Both targets exit non-zero if the replay still reports a
monitor failure.

For a `.scenario`-file failure (the DSL harness above, not
`wire_sweep`), the equivalent one-liner is the `--seed=` override
already documented under "Simulation chaos engine":
`build/bin/zclassic23-chaos --scenario=PATH --seed=0x... --verbose`.
See `docs/SIMULATOR.md`'s "Reproducing a failure" section for the
`wire_sweep` side with the fuller "why no tape parsing is needed"
rationale.

## Debugging Failures

Start with `--verbose`; the harness prints each accepted command as it runs.
If a scenario fails after a production crash, inspect the postmortem capsule
beside the scenario and reduce the command list until the failure is minimal.
For parser failures, the `chaos:LINE:` prefix points to the offending line.
The failure summary in `chaos-output/` records the seed, replay command,
scenario path, boot phase, peer counts, byte counters, clock movement,
partition drops, and the key metrics needed to promote the failure into a
checked-in regression.

Before committing a scenario, run:

```bash
ZCL_TEST_ONLY=chaos_harness build/bin/test_zcl
make chaos
```
