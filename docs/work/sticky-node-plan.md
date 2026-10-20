# THE STICKY NODE — stickiness invariants and gap analysis (design record)

**Prime invariant: STICKINESS.** Once installed/run, the node ALWAYS keeps working with
zero maintenance — no recovery recipes, no two-step `--importblockindex`, no owner-gated
surgery, no manual flags — and continuously serves the latest usable chain state. All nodes
worldwide stay robustly coordinated: behind nodes catch up unattended, forked/corrupt nodes
re-converge to canonical automatically, recovering nodes always find peers that supply what
they need.

This supersedes "fast detective tip" as the PRIME goal. Speed and sovereignty are now
*means* to stickiness, not ends. The detective frame (re-derive over trust-the-frozen-page)
remains the correct mechanism — but the new top-level law is: **a stall is always a named
blocker that fires an always-terminating remedy ladder; it is NEVER a terminal human-gated
state.** Every claim below is verified against current HEAD code, not docs.

---

## 1. THE STICKINESS INVARIANTS (concrete, testable)

- **S1 — Bounded unattended recovery from ANY on-disk state.** From any datadir state
  (fresh/empty, foreign, crash-torn, wedged, forked), a plain `z23` restart with NO
  flags reaches H* = network tip within a bounded time, with no human and no legacy datadir.
- **S2 — Every stall reaches a TERMINATING remedy.** No detected liveness-blocking condition
  may permanently give up. The remedy ladder always terminates in recovery given any honest
  peer set. `EV_OPERATOR_NEEDED` is the *last* resort for genuinely-unrecoverable local
  corruption only, never the response to a transient (oracle/peer/legacy-datadir absent).
- **S3 — Automatic re-convergence to canonical from ANY fork.** A node on a corrupt or
  equal-work-but-wrong incumbent auto-adopts the canonical chain. No human invalidateblock.
- **S4 — Peer-of-last-resort always reachable.** A recovering/partitioned node always has
  >1 bootstrap path and can always fetch headers/bodies/snapshot from the P2P network — never
  from a co-located zclassicd RPC oracle, never from `$HOME/.zclassic`.
- **S5 — Boot never crash-loops.** No boot-phase fault `_exit()`s into a Restart=always loop;
  every boot incoherence is detected and auto-re-derived, staying up degraded at worst.
- **S6 — Self-derived (sovereign), machine-checkable.** The served tip is folded from
  PoW-verified bodies + a baked anchor (G-SOV: H* climb ∧ `coins_applied_height==H*+1` ∧
  not-borrowed), asserted by a test AND a boot self-check.
- **S7 — Liveness independent of systemd.** A directly-launched binary recovers a stall
  in-process; it does not rely on `Restart=always` to come back.
- **S8 — General re-derivation invariant.** ANY stored header/verdict whose bytes do not hash
  to a PoW-valid canonical chain is auto-rejected and re-pulled from peers — one law covering
  all stages, not one bespoke condition per wedge shape.

## 2. THE GAPS (verified file:line)

- **S1/S2/S6 — Cold start is borrowed + human.** Coin set seeded from external zclassicd
  snapshot (`utxo_recovery_restore.c:369`); only proven path to tip is the human two-step
  recipe. Sovereign cure is flag-gated: `boot.c:3372` (`mint_anchor` on `ctx->mint_anchor`),
  `boot.c:3395-3398` (`do_from_anchor` on flag), `boot_refold_staged.c:390` (FATAL tells
  operator to wipe + re-import). G-SOV marker `coins_kv_contains_refold_marker()` has ZERO
  production impl (verified: grep over `--include=*.c` returns nothing).
- **S2/S8 — Wedge cure is oracle-coupled.** `stale_validate_headers_repair.c:151` backfills
  only via `header_probe_pull_range`; `header_probe.c:47-48` hardwired `127.0.0.1:8232`. No
  P2P fallback. Live oracle dead (`rpc_errors` climbing). After max_attempts=5 → page.
- **S3 — Equal-work fork = permanent stuck.** `tip_finalize_stage.c:533` rejects tips with
  `compare(new,old) <= 0`. Both fork-stall conditions gate on strictly-greater work
  (`tip_fork_stale.c:177`, `tip_stall_oracle_rebuild.c:158`); the latter also disables itself
  with no oracle (`:168-170`). Sibling-adopt fix `e8e4eb092` is **NOT on HEAD** (verified
  `git merge-base --is-ancestor` → NOT_ON_HEAD); `chain_state_service.c:435` still "equal work
  keeps the incumbent." `header_admit` re-validate (`header_admit_stage.c:298`) only fires
  *after* a reorg that the `<=0` gate prevents — so Track A's re-arm cannot fire as designed.
- **S2 — Condition engine gives up.** `condition.c:209-210`: `attempts>=max_attempts` →
  `due_for_remedy` returns false forever; re-arms only when `detect()` goes false
  (`:230-238`). All 29 conditions have max_attempts 1-5. None retries unbounded.
- **S2 — OPERATOR_NEEDED terminal latch.** `chain_tip_watchdog.c:194-207`: on
  `deterministic_stall` (the exact class every wedge produces) OR restart-budget exhaustion →
  `g_operator_needed=true`, "staying up degraded for manual intervention." Verified.
- **S2/S5 — Boot FATALs precede self-heal.** `self_heal_register` is at `boot_services.c:1463`;
  boot.c FATAL/_exit paths run earlier: coins-view integrity `_exit` at `:1728`, progress.kv
  `_exit` at `:1808`, block-index integrity FATAL at `:2515`, refold sapling `_exit` at
  `:3427`. A boot wedge crash-loops with NO in-binary remedy.
- **S2 — Dead remedy edges.** `blocker_supervisor_sweep()` (`blocker.c:379`) has ONLY test
  callers (verified grep) → blocker escape_action never fires in prod. Supervisor stall handler
  `worker_on_stall` (`boot_background_workers.c:108-124`) is observe-only (LOG_WARN + event,
  never a remedy). No top-level escalator consumes `condition_engine_get_unresolved_count()`.
- **S4 — Bootstrap SPOFs + no peer-of-last-resort in healer.** `chainparams.c:197`
  `nOnionSeeds=1`; 10 fixed IPs dated 2026-04; addrman persisted only on clean shutdown
  (`connman.c:1834`). `peer_floor_violated.c` pages after 5 attempts with no onion-directory /
  snapshot-peer fallback wired in.
- **S2 — BLOCK_FAILED auto-clear fights heal.** `boot_background_workers.c:517-543`
  unconditionally clears `BLOCK_FAILED_MASK` on h+1 every 300s → re-admits forgeries, undoes
  FAILED-based heal in <=5 min.
- **S7 — systemd-coupled restart.** `chain_tip_watchdog.c:339` requests shutdown; relies on
  `Restart=always`. Direct-launch binary stays down. 50 `EV_OPERATOR_NEEDED` sites (verified),
  each a designed human dead-end.
- **MISC — no disk-full self-heal; clock-skew on wall clock** (`condition.c:17-20`).

## 3. PRIORITIZED WORK (integrate + reprioritize Track A/B/Act3, ADD the missing)

### P0 — close the structural anti-stickiness defects

1. **TOP-LEVEL ALWAYS-TERMINATING REMEDY ESCALATOR (NEW; the keystone).** One supervisor
   child / meta-condition consumes `condition_engine_get_unresolved_count()` +
   `EV_OPERATOR_NEEDED` and drives an ORDERED ladder: retry → targeted re-derive → resnapshot
   → reindex → self-mint-anchor refold → widen peer discovery → re-bootstrap from genesis. The
   deepest rung ALWAYS succeeds given any honest peer set, so the ladder cannot dead-end at a
   human. *Why-sticky:* delivers S2 — the single law that makes a stall un-terminal.
   *Replaces* the `chain_tip_watchdog.c:194-207` OPERATOR_NEEDED latch: deterministic stall now
   fires re-derivation, not a human page. *Copy-prove/gate:* fault-injection matrix (below) on
   a regtest fixture; new lint gate "no CRITICAL liveness condition may permanently give up."

2. **GENERALIZE TRACK A: the re-derivation invariant S8 (NEW; subsumes the 3157647 cure).**
   ONE condition→remedy keyed on the hash-mismatch CLASS, not the `header-source-hash-mismatch`
   string: for any active-chain height H whose stored header/verdict bytes don't hash to a
   PoW-valid canonical chain, mark suspect → re-pull from peers → re-run the stage. The
   3157647 fix falls out. *Why-sticky:* pre-empts the whole forged-page class; ends whack-a-mole.
   *Gate:* regtest fixtures for 3+ distinct forged-page shapes must all auto-heal; gate on H*
   CLIMB not "no FATAL."

3. **PEER-SOURCED WEDGE CURE + land sibling-adopt (was Track A, now P0).** (a) Land `e8e4eb092`
   onto HEAD: adopt equal-work sibling when incumbent carries `BLOCK_FAILED_MASK`/no body —
   change the effective gate at `tip_finalize_stage.c:533` and `chain_state_service.c:435` from
   strict `>` to `> OR (==work AND incumbent failed)`. Parity-restoring (a corrupt incumbent is
   not a valid tip). (b) Give `header_probe`/`stale_validate_headers_repair` a P2P
   getheaders/getdata fallback so the canonical-solution backfill works with the oracle DEAD.
   *Why-sticky:* S3/S4 — the live 3157647 class self-heals on any node with peers, oracle gone.
   *Gate:* regtest equal-work-corrupt-incumbent fixture reconverges with NO oracle process.

4. **FIX RESTART-RE-WEDGE + SOVEREIGN-DEFAULT COLD BOOT (merge Act 3 forward, sequenced).**
   (a) When active tip is ABOVE the snapshot-load height and a persisted FAILED entry sits at
   H*+1, boot/refold invalidates+re-fetches that slot from peers instead of re-seeding below it
   and folding into the same failure (today restart deterministically re-wedges). (b) Make
   self-mint anchor + refold-from-anchor the DEFAULT boot path for empty/foreign datadirs
   (un-gate `boot.c:3372,3395-3398`), bake a from-genesis SHA3 anchor in the binary so
   `load_verify_snapshot_eligible` is true with zero flags. (c) Delete the borrowed seed
   (`utxo_recovery_restore.c:369`) and the `$HOME/.zclassic` legacy-import branch
   (`boot.c:2023-2299`) STRICTLY AFTER the default path proves G-SOV green on a fresh datadir.
   *Why-sticky:* S1/S6 — install+run reaches a self-proven tip, no recipe, no legacy datadir.
   *Gate:* G-SOV CI assertion green on a from-scratch datadir before any deletion lands.

5. **BUILD THE G-SOV TRUTH INSTRUMENT FIRST (was Track B, now P0 — it gates #4).** Implement
   `coins_kv_contains_refold_marker()` in storage + one machine-checkable assertion (H* climb ∧
   `coins_applied_height==H*+1` ∧ not-borrowed), wired as a CI gate AND a boot self-check.
   *Why-sticky:* without it S6 is unfalsifiable and #4's deletion is unsafe.

6. **BOOT SELF-HEAL BEFORE THE FATAL GATES (NEW).** Move a minimal self-heal/supervisor
   bring-up ahead of `boot.c:1728/1808/2515/3427`; convert those `_exit`/FATAL paths into
   in-process bounded re-derive (reindex/refold) or a guaranteed-terminating restart ladder
   that ends stay-up-degraded, never crash-loop. *Why-sticky:* S5 — kills the un-rebootable
   class structurally. *Gate:* fault-injected corrupt sapling/coins-view/index boots all reach
   serving-degraded without a human, under direct-launch AND systemd.

### P1 — close the give-up cliffs and peer-coordination gap

7. **Continue-with-cooldown tier for external-resource healers** (`condition.c:209-214`):
   re-arm remedy attempts on long backoff (5-15 min) for peers/oracle-dependent conditions
   instead of latching at max_attempts. Re-arm budgets on a changed fault identity (episode
   window keyed to target/hole hash, like `chain_tip_watchdog.c:183-190`). *Sticky:* S2.

8. **Decouple liveness-restart from systemd** (`chain_tip_watchdog.c:339`,
   `boot_sd_watchdog.c`): with no NOTIFY_SOCKET, perform in-process re-init/re-drive (or
   self-respawn) for the genuine-liveness class. *Sticky:* S7. *Gate:* direct-launch stall test.

9. **Peer-coordination track (NEW; the missing half of the vision).** (a) Wire
   peer-discovery-of-last-resort into `peer_floor_violated`: query hardcoded onion-directory
   seeds + snapshot-serving peers when outbound count is 0. (b) `nOnionSeeds>1`, periodic
   addrman flush (every 10-15 min + after each seed round), refresh fixed-IP set from
   long-lived addrman peers. (c) Let ANY at-tip node build+offer a snapshot (decouple from
   `boot_profile_has_file_service`); behind nodes prefer snapshot-from-any-ZCL23-peer.
   *Sticky:* S3/S4 — global reconvergence + always a supplier.

10. **Wire the dead remedy edges.** Call `blocker_supervisor_sweep()` from the self_heal tick
    so escape_actions fire; make `worker_on_stall` raise a condition/blocker (enters the ladder)
    instead of only logging. *Sticky:* S2.

11. **BLOCK_FAILED auto-clear: distinguish transient vs deterministic**
    (`boot_background_workers.c:517-543`) — only clear transient-cause failures; paired with #2
    so a genuine forgery is re-derived, not blindly un-failed. *Sticky:* S2/S8.

### P2 — robustness completeness

12. **Break the ~50 blk/s fold ceiling** (pprev-walk in `active_chain_fill_window`,
    chainstate.c:350-391 — the measured 76% bottleneck) so fallback genesis IBD and behind-node
    catch-up are tolerable. *Sticky:* S1 bounded-time clause. (NOTE: ECDSA-skip-below-anchor is
    ALREADY shipped — do not re-propose.)
13. **Disk-full condition** (ENOSPC/SQLITE_FULL → pause drains, free derived/temp, page once,
    resume on space return) + clock-skew reconciliation (monotonic vs wall in `condition.c`).

## 4. THE NEW METRIC — STICKINESS (replaces / wraps T)

**MTTUR — Mean Time To Unattended Recovery** over a fault-injection matrix, plus
**AAR — Auto-Recovery %** (fraction of fault classes that recover with zero human, zero legacy
datadir) and **GCT — Global Convergence Time** (a forked node → canonical, unattended).

- Fault matrix (each row: inject on a copy, plain restart, gate on H* CLIMB to tip):
  fresh/empty datadir; foreign datadir; mid-write kill-9; corrupt sapling tree; corrupt
  coins-view; torn index; equal-work-corrupt incumbent (3157647 class); truncated header
  solution; oracle absent; peers absent then returned; disk-full then freed; deep reorg at
  finality floor; clock jump.
- **Stickiness = AAR == 100% AND every recovered row's MTTUR is bounded AND none required a
  human, a flag, or `$HOME/.zclassic`.** v1 sticky-gate: AAR 100% on the matrix in CI.
- G-SOV green is a hard sub-gate of every row (recovered AND sovereign, not borrowed).

## 5. RED-TEAM ADDENDUM

- **R1 — "deepest rung always succeeds given any honest peer set" is conditional, not free.**
  The last-resort rung (re-bootstrap from genesis) needs peers that serve *full history* +
  a *snapshot supplier*. If the network prunes, the rung can stall. MITIGATION: ship the
  peer-coordination track (#9c — any at-tip node offers a snapshot) so the network always has
  a supplier, and make #12 (fold speed) NOT optional — a genesis re-bootstrap at ~50 blk/s is
  "recovered" but not in *bounded* time (hours). If genesis is the floor rung, its speed is a
  stickiness invariant, not P2 nicety.
- **R2 — auto-recovery must not weaken eclipse-resistance or parity.** An always-terminating
  ladder that auto-reindexes/re-bootstraps could adopt a non-canonical chain under eclipse.
  Every rung MUST verify PoW + consensus-parity + anchor-to-the-baked-checkpoint + require
  headers from K distinct peers before adopting a re-derived chain. Aggressive stickiness with
  weak peer-diversity = a new attack surface. Add an eclipse-diversity precondition to the
  escalator's adopt step.
- **R3 — recovery != correctness.** "Always reaches A tip" is dangerous; the invariant is
  "always reaches the CANONICAL, self-verified tip." G-SOV must stay a HARD sub-gate on every
  matrix row — a row that recovers to a non-sovereign/non-canonical tip is a FAIL, never a pass.
- **R4 — keep the genuinely-unrecoverable page.** Removing the OPERATOR_NEEDED *latch* (the
  reflex on a transient/recoverable stall) is right; do NOT remove the principled last-resort
  page for true local-hardware corruption (disk failing, bit-rot beyond re-derivation) AFTER
  the ladder exhausts. The lint gate should read "no CRITICAL liveness condition may give up on
  a RECOVERABLE class," not "ban the event."
- **R5 — the fault matrix must be CI-DETERMINISTIC or it becomes the next flaky gate.** Rows
  like peers-absent-then-returned, deep-reorg-at-finality, clock-jump are timing/network-coupled.
  Each must run hermetically (mock peers, injected clock, regtest anchor override). A flaky
  stickiness gate is itself anti-sticky.
- **R6 — the forward-progress durability gate is RED on `main` RIGHT NOW** and must be fixed
  early (it gates the whole matrix). `reducer_frontier_compute_hstar` floors H* at the hardcoded
  MAINNET anchor `REDUCER_FRONTIER_TRUSTED_ANCHOR=3056758` (reducer_frontier.h:41) even in the
  regtest gate, whose tip is ~34 → `cursor below hstar` → `*** LIVE WEDGE REPRODUCED *** tip=2
  want 1`. Verified identical on clean HEAD 2d8c6e70b AND the Track-A patched build, so it is
  PRE-EXISTING, not any in-flight patch. This is direct evidence for #4b (the hardcoded anchor
  must become context-appropriate) AND a blocker for trusting the forward-progress gate. Fix:
  make the trusted anchor network/context-derived (regtest gets a regtest anchor), so the gate
  can actually verify forward progress. Promote to P0-adjacent (it gates #1's matrix).
