# simnet_wire next-wave lane specs (Steps D/E/F + app-layer flows)

Grounded in the merged step A/B code (`engine/modules/sim/src/simnet_wire.c`,
`simnet_wire_peer.c`, `simnet_wire_internal.h`,
`engine/modules/sim/include/sim/simnet_wire.h`, `tests/harness/src/test_simnet_wire.c`),
`engine/modules/sim/src/simnet_cluster.c`, `engine/modules/sim/include/sim/simnet_byzantine.h`,
`engine/modules/sim/src/simnet_wallet.c`, `engine/modules/sim/include/sim/simnet_mempool.h`,
`core/modules/net/src/net_fault.c`, `core/modules/net/include/net/net.h`
(`struct net_manager`), and `tests/harness/src/test_simnet_txkit.c`. See also
[`io-harness-design.md`](./io-harness-design.md), `docs/SIMULATOR.md`,
`docs/SIMULATOR_TXNS.md`.

## 0. Ground-truth architecture facts that change the plan

These are load-bearing for Steps D/E and were not visible from the design doc
alone — read before assigning lanes.

**F0. simnet_wire models ONE real peer connection, not N independent
connections.** `simnet_wire_create()` (`simnet_wire.c:1032-1085`) calls
`p2p_node_create()` exactly once (`simnet_wire.c:315`) to build `wire->nut`.
Every `wire_peer` slot in `wire->peers[]` has its own `wire_link` (its own
`to_nut`/`to_peer` byte rings), but all of them feed bytes into that **same**
single `p2p_node`. Concretely:
- Ingress: `simnet_wire_pump_to_nut()` (`simnet_wire.c:595-657`) is called once
  per peer index in the tick loop (`simnet_wire.c:1012-1015`), and every call
  writes into `wire->nut`'s single `recv_msg_count`/`recv_msgs` queue via
  `p2p_node_receive_bytes(node, ...)`.
- Egress: `simnet_wire_drain_nut_send()` (`simnet_wire.c:765-804`) hardcodes
  `size_t peer_id = 0;` (`simnet_wire.c:784`) — the NUT's single `send_head`
  list is always routed to peer slot 0 only. Peers 1..N-1 are ingress-only.
- Handshake: `wire_start_stream_adversary()` (`simnet_wire_peer.c:236-248`)
  only sends `version` when `peer_id == 0` (`simnet_wire_peer.c:245`) — other
  peer slots never complete their own handshake state; they are additional
  byte sources hitting the one connection's parser/backpressure/ban logic.

This means today's "peer_count" parameter really means "number of
simultaneous adversarial byte sources aimed at one honest connection" — it is
correct infrastructure for flood/malformed/slowloris/checksum robustness
(what Step B tests), but it is **not** a multi-connection net_manager model.
Step D (eclipse/partition) and Step E (per-link bandwidth/reorder across
multiple peers) both implicitly assume N independently-stateful peer
connections. Building that is a bigger lift than the design doc's one-line
build-order entry suggests, and step D's lane below is written as an
explicit prerequisite fork: either (a) scope "eclipse/partition" down to
single-link semantics that already fit the current model (recommended, see
D1 below), or (b) do the N-`p2p_node` refactor first (see D2, sized "L" not
"M").

**F1. `net_partition_until_unix()` is a single global atomic
(`core/modules/net/src/net_fault.c:8-16`, `g_net_partition_until_unix`), not per-peer.**
It is honored at `net.c:432` and `msgprocessor.c:1657` per the design doc.
A real eclipse attack (attacker retains its own links to the NUT while all
honest links are cut) cannot be expressed with this global switch — it
partitions everything or nothing. The per-peer primitive that already exists
and *does* support selective partition is `wire_link.open`
(`simnet_wire_internal.h:55`), toggled today only by
`WIRE_EVENT_OPEN`/`WIRE_EVENT_CLOSE` inside `simnet_wire_deliver_one_event()`
(`simnet_wire.c:567-577`) — but **no producer ever enqueues those two event
kinds**; they are dead code paths as of step B. Step D should build on
`wire_link.open` (per-peer, already wired to ingress/egress checks at
`simnet_wire.c:603` and `simnet_wire.c:785`), not on `net_partition_until_unix`
— reserve the global partition for a "whole-node cut off from everything"
scenario, which is a different, narrower case than eclipse.

**F2. Bandwidth tokens exist but are inert.** `wire_link.down_tokens` /
`up_tokens` (`simnet_wire_internal.h:56-57`) are consulted in
`simnet_wire_pump_to_nut()` (`simnet_wire.c:623-624`) and
`simnet_wire_drain_nut_send()` (`simnet_wire.c:793-795`), but every peer is
initialized with `SIZE_MAX` (`simnet_wire.c:1069`) and nothing ever lowers
them. Step E's bandwidth-shaping work is "flip on a knob that's already
there," not new plumbing — smaller than the design doc's "M" size suggests
for the bandwidth half; the reorder/replay half is the real work (see E1/E2).

**F3. `wire_scenario.duration_us` is parsed but unused** — see
`simnet_wire_create_scenario()` ending `(void)scenario->duration_us;`
(`simnet_wire_peer.c:477`). Any lane that wants scenario-timed events
(partition-at-tick-N, reorder window, flood start offset) needs to actually
consume this field or add a timeline mechanism; today the only clock driver
is delivery-event latency jitter (`simnet_wire.c:387-391`,
`SIMNET_WIRE_MIN_LATENCY_US`/`SIMNET_WIRE_LATENCY_SPAN_US`/
`SIMNET_WIRE_REORDER_SPAN_US`, `simnet_wire_internal.h:29-31`) — reordering
already exists as *jitter noise*, not as an *adversarial scripted reorder*.

**F4. Step C is in-flight and NOT clean.** Branch `sim/wire-byzantine-c`
(`git log --oneline -5`) is at commit `c3c248181 WIP checkpoint: simnet_wire
step C byzantine bridge (18 test failures)`, then a merge-from-main on top.
It adds `engine/modules/sim/src/simnet_wire_byzantine.c` (536 lines), extends
`simnet_wire.h`/`simnet_wire_internal.h`/`simnet_wire.c`/`simnet_wire_peer.c`,
and swaps `wire->mp.block_submit` from the step A/B stub
(`simnet_wire_stub_submit_block`, `simnet_wire.c:199-208`, which
`LOG_FAIL`s on any submit) to `simnet_wire_byzantine_submit_block` — a real
block-accepting path, but scoped to the byzantine-artifact tier only. Do not
assume Step C is done; the lanes below treat it as "expected to land soon"
but the app-layer flow lane (item 2 below) needs its own non-byzantine
`block_submit`/mempool-relay wiring regardless of whether C lands clean,
since C's submit path is purpose-built for injected-bad-artifact assertions,
not general tx/block relay.

## 1. Step D — eclipse / partition scenarios

**Scope decision (read F0/F1 above first):** build D as **per-link
partition using the existing `wire_link.open` + `WIRE_EVENT_OPEN/CLOSE`
plumbing**, scaled to N adversarial+honest peer slots that already share the
one NUT connection model. This models "the NUT loses its connection to some
of its peers while others remain reachable" — the correct scope for a
node-liveness/recovery test (does the node keep making progress on its
remaining honest link, does the supervisor/watchdog notice a shrunk peer
count) without requiring the full N-`p2p_node` net_manager refactor (D2,
scoped as a separate, larger, OPTIONAL follow-up if the team decides true
addrman-poisoning eclipse coverage is wanted later — flag this scope choice
to the owner explicitly since it is a real fork, not an implementation
detail).

### D1 — per-link partition/recovery (recommended scope)

- **Files (new/changed, disjoint from D2/E/F)**:
  - `engine/modules/sim/src/simnet_wire.c` — add `simnet_wire_partition_peer(wire,
    peer_id, bool closed)` that enqueues `WIRE_EVENT_CLOSE`/`WIRE_EVENT_OPEN`
    for that peer_id (currently dead code paths per F1 — wire them to a
    public entry point). Add a monitor: "if a peer's link closes while
    others remain open, and a majority of peers close, does the harness
    still make progress via the honest survivor" (mirrors the existing
    slowloris-recovery pattern in `test_simnet_wire.c:164-197`).
  - `engine/modules/sim/include/sim/simnet_wire.h` — add
    `simnet_wire_partition_peer()` declaration + a `struct
    wire_scenario_partition { size_t peer_id; uint64_t at_tick;
    uint64_t duration_ticks; }` timeline entry type, and extend `struct
    wire_scenario` with an optional `partitions[]`/`partition_count` so
    `simnet_wire_create_scenario()` can script them (this finally consumes
    F3's dead `duration_us`-style timing need, but keyed off tick count —
    keep determinism, don't add wall-clock).
  - `engine/modules/sim/src/simnet_wire_internal.h` — extend `struct wire_scenario_peer`
    handling only if the partition timeline needs peer-local bookkeeping
    beyond `wire_link.open` (likely not — reuse the existing field).
  - `tests/harness/src/test_simnet_wire.c` — new `test_simnet_wire_partition_*`
    functions (parallel to the existing `sw_run_*` static helpers), plus
    registration in `tests/harness/src/test.c` (mirror the block at
    `test.c:21-68` for the `simnet_wire` argv-subset dispatch).
- **Approach**: script N adversarial/honest peers via
  `simnet_wire_create_scenario()`; at a chosen tick, close the honest peer's
  link (or the majority) while an attacker-kind peer (e.g.
  `SIMNET_WIRE_PEER_INVALID_BLOCK`/`FLOOD`) stays open; assert the node does
  NOT silently halt (checks `blocker_snapshot_all` per the existing
  `simnet_wire_monitor_blockers()` at `simnet_wire.c:910-925`, and/or
  `supervisor`/`watchdog` liveness state if reachable from this harness —
  check whether `platform/modules/util/src/supervisor.c` state is queryable without a
  running node; if not, that is itself a gap to name, not silently skip).
  Then reopen the honest link and assert recovery (ping/pong round-trip,
  same pattern as `sw_run_slowloris`'s recovery-nonce check,
  `test_simnet_wire.c:172-179`).
- **Acceptance gates**: `make -j8 build-only`; `make t ONLY=simnet_wire`
  (or the new sub-group name once registered, following the `test.c:31-64`
  pattern); determinism check — same seed, same fingerprint, same as every
  existing `sw_run_*` test does with the `fp_a == fp_b` pattern
  (`test_simnet_wire.c:257-258` etc). `make lint`.
- **Model tier: Sonnet.** Mechanically extends an established pattern
  (per-peer link toggling already exists; wiring a public API + scenario
  timeline + tests is well-scoped, not novel-hard).

### D2 — true multi-connection eclipse (OPTIONAL, larger, name explicitly to owner before starting)

- Would require: N separate `struct p2p_node` instances registered in one
  `net_manager` (mirroring how the real node's `connman` holds
  `nm.nodes[]`, `net.h:329-331`), each pumped independently through
  `msg_process_messages`, plus addrman-level peer-selection modeling so an
  "eclipse" can be expressed as "NUT's outbound slots are ALL attacker
  addresses." This is genuinely a different, bigger harness shape than
  steps A-D1 (multi-node, not single-connection-with-many-senders) — do not
  fold it into D1's estimate. If the owner wants it, size it as its own
  wave, not a D sub-lane.
- **Model tier if pursued: Opus** (architecture-level extension touching
  `net_manager` semantics, not mechanical).

## 2. Step E — replay/reorder/bandwidth-shaping + fingerprint determinism

- **Files**:
  - `engine/modules/sim/src/simnet_wire.c` — bandwidth: replace the `SIZE_MAX`
    initialization at `simnet_wire.c:1069` with a scenario-configurable cap;
    thread it through the already-present `down_tokens`/`up_tokens`
    consultation sites (`simnet_wire.c:623-624`, `simnet_wire.c:793-795`) —
    per F2 this is a small, low-risk change since the consultation logic
    already exists and is exercised by the flood/slowloris tests (just
    always non-binding today). Reorder: add an explicit **adversarial**
    reorder primitive distinct from the existing latency-jitter reorder
    noise (F3) — e.g. a peer kind or scenario flag that intentionally
    delivers header/block-announcement frames out of causal order (headers
    for height N+1 before N) to exercise the node's out-of-order handling,
    not just network jitter. Replay: a peer kind that re-sends a
    previously-accepted frame (tx/block/inv) verbatim after some delay —
    assert idempotent handling (no duplicate processing side effect, no
    monitor violation).
  - `engine/modules/sim/src/simnet_wire_peer.c` — new adversary kinds/branches:
    `SIMNET_WIRE_PEER_REPLAY` already has an enum value
    (`simnet_wire.h:30`, `SIMNET_WIRE_PEER_REPLAY = 8`) but is currently
    routed to `wire_mark_not_implemented()` (`simnet_wire_peer.c:303`,
    the catch-all default branch in `simnet_wire_start_peer_kind()`) —
    confirm via `not_implemented_peers` stat
    (`simnet_wire_get_stats()`, `simnet_wire.c:1232`) which kinds are
    currently stubs before claiming "already have a REPLAY peer": the enum
    exists, the behavior does not.
  - `engine/modules/sim/include/sim/simnet_wire.h` — extend `wire_scenario_peer` or add
    a sibling struct for bandwidth caps if scenario-level configuration is
    wanted (vs. a direct `simnet_wire_set_link_bandwidth(wire, peer_id,
    down_cap, up_cap)` setter — prefer the setter; simpler, matches the
    existing imperative `simnet_wire_start_*` API style rather than growing
    `wire_scenario` further).
  - `tests/harness/src/test_simnet_wire.c` — new focused tests per adversary
    kind, following the existing `sw_run_*` + `SW_CHECK` pattern exactly
    (`test_simnet_wire.c:18-22` macro, `72-243` for the per-kind runner
    shape).
- **Approach**: reuse `simnet_wire_fnv_bytes`/`simnet_wire_fp_mix`
  (`simnet_wire.c:45-72`) for the determinism fingerprint — no new fingerprint
  mechanism needed, it is already seeded from real delivered bytes per
  direction. For bandwidth, verify a FLOOD peer under a small `down_tokens`
  cap produces *bounded, cap-respecting* throughput (assert
  `delivered_to_nut_bytes` growth per tick stays ≤ cap, not just that the
  recv queue stays bounded — that is the new assertion this lane adds beyond
  what Step B already checks).
- **Acceptance gates**: same as D1 (`build-only`, `make t ONLY=simnet_wire`,
  determinism replay of identical seed, `make lint`).
- **Model tier: Sonnet** for REPLAY/reorder peer kinds and tests (mechanical,
  same shape as existing FLOOD/SLOWLORIS code); **Haiku** is plausible for
  just wiring the already-dead bandwidth tokens live (small, bounded diff) if
  split into its own sub-lane — see lane table below.

## 3. Step F — nightly wire_sweep runner + failure capsule save

- **Files (new)**:
  - `tools/sim/wire_sweep.c` — model on the existing `tools/sim/chaos.c`
    pattern (standalone `cc`-compiled binary, not part of the whole-program
    LTO build — see `Makefile:774-784` for the `zclassic23-chaos` target
    shape to copy). Loop over a seed range (or `--seed=N --count=K`),
    construct a `wire_scenario` per seed (mix of peer kinds proportional to
    a config, similar to `sw_run_mixed` in `test_simnet_wire.c:199-243` but
    seed-driven rather than fixed), run under `ASan`/`UBSan` (already how
    `FUZZ_TARGETS` are built per `Makefile:1582` and the CI tier note in
    `docs/work/io-harness-design.md:80-82`), and on any monitor failure call
    `simnet_wire_save_capsule(wire, path)` (already implemented,
    `simnet_wire.c:847-857`, and also auto-invoked internally by
    `simnet_wire_mark_monitor_failed()`, `simnet_wire.c:859-875`, into
    `/tmp/simnet_wire_<seed>.tape` — wire_sweep.c should additionally save
    to a stable, git-ignored artifact directory since `/tmp` capsules do not
    survive CI runners, and print the failing seed to stdout for replay).
  - `Makefile` — new `wire-sweep` target (thousands of seeds, excluded from
    `make ci`/`make test`, analogous to how `fuzz`/`fuzz-ci` are separated
    from `test` at `Makefile:1599`/`1647`). Add the grep security-gate the
    design doc calls for (`docs/work/io-harness-design.md:65-68`): CI-time
    `grep` over `engine/modules/sim/src/simnet_wire*.c` + `tools/sim/*wire*` asserting
    no `recv(`/`send(`/`socket(`/`connect(`/`bind(`/`getaddrinfo(` — **this
    gate now EXISTS and is wired**: `make check-wire-harness-security-gate`
    (`tools/scripts/check_wire_harness_security_gate.sh`), in `LINT_GATES` and
    in `run_lint.sh`. Nothing to add; extend its scan set if the harness grows
    new files.
    <!-- claim: file-present tools/scripts/check_wire_harness_security_gate.sh # the gate is built -->
    <!-- claim: gate-passes check-wire-harness-security-gate # and the harness stays socket-free -->
  - `engine/modules/sim/src/simnet_wire.c` (touch only if capsule replay needs a load
    path — check `seed_tape` API for a load/replay entry point before
    assuming one needs to be added; `engine/modules/sim/src/seed_tape.c` likely already
    supports open-from-file since `seed_tape_save`/`seed_tape_open` are
    symmetric — confirm before writing new replay code).
- **Approach**: nightly-only, thousands of seeds, one seed per adversary-kind
  mix per the design doc's CI-tier note (`io-harness-design.md:80-82`: "CI
  tier: ~8-12 seeds... Nightly: tools/sim/wire_sweep.c, thousands of seeds").
  Keep it out of `make ci`/`make test` entirely — this is explicitly a
  nightly/soak-class artifact per the same doctrine that excludes
  soak/fuzz from CI (see `docs/work/lint-gate-hollowness-audit.md` framing
  and the existing `fuzz-ci` vs `fuzz` split as precedent).
- **Acceptance gates**: `make wire-sweep SEEDS=200` (short local smoke run)
  completes with zero monitor failures on current step A/B (+ C once landed)
  code; a deliberately-reverted regression (e.g. temporarily disable one
  monitor check) is caught by the sweep to prove the gate has teeth (same
  "prove the fix FIRES" discipline the project already requires for
  recovery-path work). `make check-wire-harness-security-gate` (new) passes.
- **Model tier: Sonnet** for the runner + Makefile wiring (mechanical,
  closely modeled on `chaos.c`); have a second Sonnet pass specifically
  verify the grep security gate actually fires on a deliberately-reintroduced
  `socket(` call before trusting it (a hollow lint gate is a known project
  failure mode per `docs/work/lint-gate-hollowness-audit.md`).

## 4. App-layer flows through the harness

### (a) ZNAM/ZName registration via OP_RETURN through connect_block with adversarial peers present

- **Already present**: `znam_build_register()` and siblings
  (`contexts/naming/modules/znam/include/znam/znam.h:97-126`) build the OP_RETURN payload;
  `simnet_wallet_op_return()` (`engine/modules/sim/src/simnet_wallet.c:534`,
  declared `engine/modules/sim/include/sim/simnet_wallet.h:61-64`) already builds,
  fees, and enqueues an OP_RETURN carrier tx; `simnet_mempool_add`/
  `simnet_mempool_mint` (`engine/modules/sim/include/sim/simnet_mempool.h:48-59`)
  already mines it through real `connect_block()`. This whole chain is
  proven today via `simnet` (not `simnet_wire`) — see `docs/SIMULATOR.md`'s
  "ZNAM REGISTER | A" row and `make t ONLY=simnet`.
- **Missing for the wire-integrated version**: the ONLY new work is bridging
  a mined block (containing a ZNAM OP_RETURN tx) onto the P2P wire so an
  adversarial peer set is genuinely present during relay/validation, not
  just during direct `connect_block()`. `simnet_wire`'s `block_submit` hook
  is a `LOG_FAIL`-on-any-submit stub in steps A/B
  (`simnet_wire_stub_submit_block`, `simnet_wire.c:199-208`); Step C's
  `simnet_wire_byzantine_submit_block` (branch `sim/wire-byzantine-c`,
  `engine/modules/sim/src/simnet_wire_byzantine.c`) is scoped to byzantine-artifact
  assertions, not general relay. **Concrete gap**: write a
  `simnet_wire_app_submit_block()` (or extend the byzantine one, name TBD by
  whoever lands C first) that runs the submitted block through the SAME
  `connect_block()` path `simnet`/`simnet_wallet` already use, then have a
  test mint a ZNAM-carrying block via `simnet_wallet_op_return` +
  `simnet_mempool_mint`, hand the serialized block to `simnet_wire` as an
  inbound `block` message from an honest peer while a
  `SIMNET_WIRE_PEER_FLOOD`/`INVALID_BLOCK` peer is also attached, and assert
  (i) the block is accepted, (ii) the ZNAM projection would resolve it (if a
  projection DB is opened the same way `test_simnet.c` does), (iii) the
  adversarial peer's noise did not affect acceptance or the tip/coins
  monitor baselines.
- **Files**: `engine/modules/sim/src/simnet_wire_app.c` (new, disjoint from D/E/F and
  from the byzantine bridge) + `engine/modules/sim/include/sim/simnet_wire_app.h` (new)
  + `tests/harness/src/test_simnet_wire_app.c` (new). Reads-only from
  `engine/modules/sim/src/simnet.c`, `simnet_wallet.c`, `simnet_mempool.c` (reuse, don't
  duplicate their tx-building logic — call them).
- **Model tier: Sonnet** (integration of already-proven pieces; the
  `connect_block` plumbing pattern already exists in `simnet.c` to copy).

### (b) ZSLP token txs

- **Already present**: `slp_build_genesis`/`_mint`/`_send`
  (`contexts/market/modules/zslp/include/zslp/slp.h:73-89`) + the same
  `simnet_wallet_op_return()` + `simnet_mempool_add/mint` path. Proven via
  `simnet` today (`docs/SIMULATOR.md`: "ZSLP GENESIS/SEND/MINT | A").
- **Missing**: identical gap to (a) — wire-level relay-with-adversaries
  integration. No new tx-building infra needed; same `simnet_wire_app.c`
  lane covers both (a) and (b) — do not split into two lanes, they share
  every piece except the payload builder call.
- **Model tier: folded into (a)'s Sonnet lane.**

### (c) Escrow/HTLC

- **Correction to the task's framing** — HTLC redeem/refund settlement is
  **already implemented and tested end-to-end**, not just "script builders
  exist." `tests/harness/src/test_simnet_txkit.c` (`txk_htlc_scripts()` at
  line 149, `txk_build_htlc_spend()` at line 177) drives the real
  `core/modules/script/src/htlc.c` builders through `simnet_wallet_send()` (P2SH
  fund) → `simnet_mempool_add`/`simnet_mempool_mint` (redeem and refund,
  including a real timelock-finality gate via
  `simnet_mint_to_height`) — see the "P2SH HTLC fund" / "HTLC redeem path" /
  "HTLC refund path" rows in `docs/SIMULATOR_TXNS.md`'s transaction catalog,
  with real measured sizes/fees. **`docs/SIMULATOR.md`'s own action-coverage
  table is stale here** — it still lists "HTLC redeem scriptSig build" and
  "HTLC refund scriptSig build" as Class B ("simnet lacks a
  mempool/timelock/script execution flow for settlement"), which was true
  before `test_simnet_txkit.c` landed and is not true now. Flag this doc
  drift for a fix (small doc-only change, Haiku-appropriate, not part of
  this wave's code lanes but worth a one-line follow-up).
- **What's actually missing**: (i) wire-level integration, same shape as
  (a)/(b) — fold into the `simnet_wire_app.c` lane once it exists (fund via
  wallet, mine, relay the funding+redeem/refund txs over the wire with
  adversarial peers present, assert consensus-unchanged monitor holds and
  the correct party's redeem/refund succeeds). (ii) the ATOMIC SWAP
  controller layer (`engine/controllers/src/swap_controller.c`,
  `swap_initiate`/`swap_participate`/`swap_list`) remains Class C per
  `docs/SIMULATOR.md` — it builds local state but doesn't drive on-chain
  settlement through simnet; that is a controller-integration gap distinct
  from the HTLC script/settlement gap, and cross-chain (BTC/LTC/DOGE) legs
  are out of scope for this repo's simulator entirely (no counterparty
  chain to simulate against). Do not conflate "HTLC settlement in simnet"
  (done) with "swap_controller state machine reaches FUNDED/REDEEMED via
  simnet" (not done, and arguably out of scope until real cross-chain
  broadcast exists).
- **Model tier: Sonnet** for the wire-integration slice (folds into (a)'s
  lane); do not staff a lane for swap_controller cross-chain settlement in
  this wave — no counterparty chain exists to make it meaningful yet.

### (d) Sapling shielded send in-sim

- **Confirmed NOT feasible today**, and this matches `docs/SIMULATOR.md`'s
  own Phase-2 roadmap (no doc drift here, unlike HTLC). Evidence:
  `engine/modules/sim/src/simnet.c:35-36` picks the harness's mint height explicitly
  "low enough that Sapling is inactive (so the all-zeros
  hashFinalSaplingRoot check is skipped)"; every `block_index` the simulator
  builds sets `has_chain_sapling_value = false` (`simnet.c:195,237`;
  `simnet_chain.c:302,529`; `simnet_byzantine.c:485`). There is no Sapling
  note/tree/anchor/nullifier state anywhere in `engine/modules/sim/`. A grep for
  "sapling" across `engine/modules/sim/` returns only these sapling-is-OFF markers —
  zero note-commitment-tree or memo-field code.
  `docs/work/sim-phase2-plan.md` exists and is the right place to check for
  a design before starting; it was not read in depth here (out of scope for
  this pass) but should be the first read for whoever staffs this.
- **What's missing, concretely, to make (d) possible**: (1) a
  post-Sapling-activation synthetic checkpoint (the `simnet` harness already
  has the mechanism — a synthetic covering checkpoint per
  `docs/SIMULATOR.md`'s Model section — the gap is only that today's chosen
  height is deliberately pre-activation); (2) Sapling note commitment tree +
  anchor tracking in the coins view (real `coins_view_cache` may already
  carry Sapling tree state for the real node — check
  `core/modules/coins/include/coins/coins_view.h` before assuming new state is
  needed, since the simulator reuses the real `coins_view_cache` type); (3) a
  shielded-spend/output builder analogous to `simnet_wallet_send()` but
  producing Sapling Spend/Output descriptions with real Groth16 proofs (or,
  for a lower-effort first cut, with `expensive_checks=false` proof
  skipping — same trick `docs/SIMULATOR.md`'s Model section already uses for
  PoW/script, confirm whether Sapling proof verification is similarly
  gateable before assuming full proving is required); (4) memo-field
  plumbing if the goal includes the ZMSG Sapling-memo channel
  (`docs/SIMULATOR.md`: "ZMSG Sapling memo channel | B" — messaging
  controller hardcodes P2P today per project CLAUDE.md's ZCL Messaging
  section).
- **This is a real, separately-sized feature, not a wire-integration
  add-on** — it needs coins-view/Sapling-tree research before any code, and
  should NOT be folded into the same wave as (a)/(b)/(c) or into Steps
  D/E/F. Recommend a dedicated research spike (read
  `docs/work/sim-phase2-plan.md` + `core/modules/coins/include/coins/coins_view.h` +
  wherever the real node keeps its Sapling tree) before writing an
  implementation-ready spec for it.
- **Model tier: Opus for a future implementation lane; this wave's action
  item is a Sonnet or Opus RESEARCH task only** (produce a design, not code)
  — do not staff an implementation lane for (d) in this wave.

## 5. Lane decomposition (disjoint file sets, parallel-safe)

| Lane | Scope | New/changed files (disjoint) | Depends on | Model tier |
|---|---|---|---|---|
| **L1 — Step D1** | per-link partition/recovery scenarios | `engine/modules/sim/src/simnet_wire.c` (add partition API + monitor), `engine/modules/sim/include/sim/simnet_wire.h` (new API + scenario timeline struct), `tests/harness/src/test_simnet_wire.c` (new tests), `tests/harness/src/test.c` (registration) | step A/B (merged) | **Sonnet** |
| **L2 — Step E** | REPLAY peer kind, adversarial reorder, live bandwidth caps | `engine/modules/sim/src/simnet_wire_peer.c` (new adversary logic), `engine/modules/sim/src/simnet_wire.c` (bandwidth cap wiring — touches same file as L1; **sequence L1 then L2, don't run concurrently on simnet_wire.c**, or split by function region and merge carefully), `engine/modules/sim/include/sim/simnet_wire.h` (setter API), `tests/harness/src/test_simnet_wire.c` (new tests, additive) | step A/B; independent of D2 | **Sonnet** (bandwidth-only slice could be **Haiku** if split out) |
| **L3 — Step F** | nightly wire_sweep + capsule save + security grep gate | `tools/sim/wire_sweep.c` (new), `Makefile` (new targets), possibly `engine/modules/sim/src/seed_tape.c` (only if replay-from-file is missing — verify first) | step A/B; benefits from C for byzantine-mix seeds but doesn't require it | **Sonnet** (runner + Makefile); **Sonnet verify pass** specifically for the security grep gate |
| **L4 — App flows (a)+(b)+(c)-wire-slice** | ZNAM/ZSLP/HTLC relay-with-adversaries through simnet_wire | `engine/modules/sim/src/simnet_wire_app.c` (new), `engine/modules/sim/include/sim/simnet_wire_app.h` (new), `tests/harness/src/test_simnet_wire_app.c` (new) | step C landing (needs a real, non-byzantine-stub `block_submit`/mempool-relay path) OR write its own submit hook if C is delayed | **Sonnet** |
| **L5 — Doc fix** | correct `docs/SIMULATOR.md`'s stale HTLC Class-B rows to reflect `test_simnet_txkit.c` reality | `docs/SIMULATOR.md` only | none | **Haiku** |
| **L6 — Sapling research spike** | design doc for shielded-send-in-sim (NOT code) | new doc under `docs/work/` (or extend `sim-phase2-plan.md`) | read `docs/work/sim-phase2-plan.md` + coins_view Sapling state first | **Opus** (research/design only) |

**Sequencing note**: L1 and L2 both touch `engine/modules/sim/src/simnet_wire.c` and
`simnet_wire.h`. Land L1 first (it also introduces the scenario-timeline
struct L2's bandwidth setter can reuse), then rebase L2. L3 and L4 touch
disjoint new files and can run fully parallel to L1/L2 and to each other.
L5 is a trivial one-file doc fix, run it any time, zero conflict risk. L6
produces no code this wave — run it in parallel with everything else, gates
nothing.

**Haiku+codex→Sonnet-verify workflow** (per project doctrine, proven
2026-07-09): for L1/L2/L3/L4, consider implementing with
`codex exec --dangerously-bypass-approvals-and-sandbox` inside a Haiku
subagent, then have a separate Sonnet subagent independently run
`make -j8 build-only && make t ONLY=simnet_wire && make lint` plus read the
diff before accepting. Do not blindly trust the implementer's self-report.

## 6. Contradictions / stale-doc findings hit during this pass

1. **`docs/SIMULATOR.md`'s action-coverage table is stale for HTLC.** It
   marks HTLC redeem/refund scriptSig build as Class B ("simnet lacks a
   mempool/timelock/script execution flow for settlement"), but
   `tests/harness/src/test_simnet_txkit.c` and `docs/SIMULATOR_TXNS.md`'s own
   transaction catalog show real, working, measured HTLC fund/redeem/refund
   through `simnet_mempool_add`/`simnet_mempool_mint` with real timelock
   finality. `docs/SIMULATOR_TXNS.md` (the newer doc) is correct;
   `docs/SIMULATOR.md`'s matrix predates it and was not updated. Recommend
   fixing (L5) so the next reader doesn't re-derive HTLC settlement as "not
   yet possible."
2. **The task brief's assumption that OP_RETURN tx building is missing from
   `simnet_wallet` is incorrect** — `simnet_wallet_op_return()` already
   exists and is used by both ZNAM and ZSLP tests via `simnet` (not yet via
   `simnet_wire`). The real, still-open gap is wire-level relay-with-
   adversaries integration (see section 4a/4b), not the payload builder.
3. **The design doc's Step D "eclipse/partition ... via net_fault" line
   undersells the eclipse-modeling gap.** `net_partition_until_unix()` is a
   single global flag (`net_fault.c:8-16`); it cannot express "some peers
   cut, others not," which is the definition of eclipse. The per-peer
   primitive that can (`wire_link.open` + the currently-dead
   `WIRE_EVENT_OPEN`/`CLOSE` paths) is a different mechanism than the one
   the design doc names. This wave's D1 spec uses the per-peer mechanism and
   explicitly scopes out true addrman-level eclipse (D2) as a separate,
   larger, owner-decision item — flagged rather than silently narrowed.
4. **Step C (`sim/wire-byzantine-c`) is WIP with 18 known test failures** as
   of the branch's own commit message, then merged from main once since —
   its current state was NOT re-verified as part of this research pass
   (out of scope: read-only research, no build was run against that
   branch). Whoever picks up L4 should re-check `git log
   sim/wire-byzantine-c` and run its tests fresh before depending on its
   `block_submit` hook.
