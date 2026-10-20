# FAIL-SAFE ARCHITECTURE — the progress law + universal repair ladder

**Design record for making "stuck-needs-a-human" structurally impossible.**
Supersedes per-class whack-a-mole; absorbs
[`sticky-node-plan.md`](./sticky-node-plan.md) and `never-stuck-plan.md` §1b.

## 0. Motivation

A live stall class was traced end-to-end: a routine 1-block reorg's cleanup
step could delete stale verdict rows without rewinding the cursors that
pointed at them, manufacturing a rowless hole that no existing repair layer's
domain covered — and the healer condition, the blocker registry, and the
advertised deep-repair ladder each independently failed to close it. This
design generalizes the fix so any future birth mechanism for that class of
hole is cured by construction instead of requiring a new bespoke healer.

## 0b. The structural defects (each verified at file:line)

| # | Defect | Where |
|---|--------|-------|
| D1 | **Open blocker space, enumerated healers.** Owner hint = 3-string reason lookup; `log_hole` unowned by construction; proof/utxo logs have no reason column at all (dump.c:218-220). Healer detects pattern-match specific shapes; anything else is invisible. Nothing enforces totality. | `reducer_frontier_dump.c:69-82`, `reconcile_light.c:227-238` |
| D2 | **Fire-once meta-machinery.** Active + !detect + !witness ⇒ zombie (no retry/page/clear, forever). Pages keyed to attempts≥max, not age. Legacy conditions latch permanently at max_attempts (condition.c:220-221). Blocker escapes: 1 of N registered binary-wide; unregistered escape latches "operator must clear" (blocker.c:407-414); deadline-less blockers never sweep (blocker.c:397). | `condition.c:288-296,366-401`, `blocker.c` |
| D3 | **No progress law.** Nothing enforces "header frontier ahead + H\* flat ⇒ escalation running." Supervisor watches ticks, not outcomes. Frontier blockers never reach the typed registry. One stale PERMANENT blocker makes every stall read "deterministic" and disables the restart rung globally (chain_tip_watchdog.c:296-297). | watchdog/supervisor layer |
| D4 | **Repair layers can CREATE unowned states.** purge_noncanonical manufactures rowless holes assuming another layer heals them; the assumed healer refuses below the coins floor. Also: purge never touches utxo_apply_log/coins, so an orphaned block's coins stay applied with contiguity intact — **silent coins divergence with no tear signal** (safety, not just liveness). | `purge.c:129-255`, `refill.c:25-30,385-391` |
| D5 | **The guaranteed last rung doesn't exist.** Only executable UTXO rewind base = the single compiled anchor at 3,056,758 (checkpoints.c:86-104). The per-1000-block seal ring is LIVE write-side (co-committed in the utxo_apply txn, `utxo_apply_stage.c:465`, `seal_service.c:127`) but the rewind consumer is comment-only vaporware (`seal_kv.h:7`); seals record coins_sha3 but not the set; sha3_windows_verify has zero callers; the XOR mmr_commitment is dead/forgeable. | mapper R4 findings |

Historical confirmation: all ~12 stall classes since May reduce to the same
shape — *state at height h contradicts the fold/log contract via some birth
mechanism the enumerated healers don't recognize* (borrowed-seed rowless span,
torn snapshot coin holes, truncated header solution, stale terminal verdicts,
finalize/download deadlock, pointer-identity freeze, XOR-audit latch, fork
residue, this hole). Every cure so far was instance- or class-specific.

## 0c. Synthesis of the two independent designs (both completed 2026-07-02)

Two designers worked the same maps from opposite frames and CONVERGED; the
final architecture is their union — B prevents births, A guarantees response:

**Design B — LOG-CURSOR CONTIGUITY (LCC), the prevention side.** Invariant:
for every success-checked stage log L with cursor C and trusted base B, every
height in [B+1, C) has a row in L at every commit boundary. Two write rules
imply it, enforced at the single cursor-write chokepoint (not caller
discipline):
- **RAISE rule**: a cursor moves up only in a transaction that inserts the
  covering row (the normal `stage.c:441-476` step already does this) or
  raises the trusted base itself in the same tx with the complete state
  commitment and explicit trust posture. A block hash alone names a chain
  location; it does not authenticate UTXO or shielded state.
  `seed_exempt` (caller-declared trust) is DELETED; the only exemption is
  `target <= trusted_base+1` where the base is a durable crypto-vetted fact.
- **DELETE rule**: a transaction deleting a row at h must, in the same
  transaction, lower that cursor and every downstream cursor to ≤ h, and
  inverse-rewind coins to h when h is below the coins frontier — exactly the
  shape `reducer_frontier_replay_stale_script_tx` already implements
  (`replay_tx.c:297-365`).
- **The universal primitive `stage_rederive_range(db, ms, lowest_stage, h)`**:
  factor that replay tx into one general entry — created_outputs backfill +
  inverse-delta coins rewind iff needed + delete rows [h, cursor) in the
  stage log and all downstream logs + lower cursors + commit; the forward
  fold rewrites fresh verdicts from PoW-verified on-disk bodies. Idempotent,
  bounded, needs no peer (bodies are local; absent bodies go through normal
  body_fetch). This one primitive replaces the detector zoo AND the refill
  layer. The ONLY row it never touches: a genuine consensus reject (ok=0,
  terminal status, stored hash == canonical) — the parity-correct named halt.
- **Deletion list** (every remaining hole factory, verified): purge without
  clamp (`purge.c:105-268`), `seed_exempt` (`stage_anchor.c:191` + plumbing),
  boot force-raise (`stage_repair.c:127`), `ZCL_REPLAY_COUNT_ONLY` cursor
  advance (`utxo_apply_stage.c:328-348` — the last second writer),
  `stage_repair_force_stage_cursor` as a raise primitive (becomes lower-only).
- **Ratchet**: post-commit O(log n) first-gap assertion after every
  repair/seed tx (a hole birth becomes a loud LOG_FAIL naming stage+height,
  never a silent pin) + lint gate restricting stage_cursor writes to the
  chokepoint TUs.

**Design A — TOTAL REPAIR FUNCTION, the response side.** Closed stall-kind
enum minted in one header; `repair_owner` keyed on KIND (never reason
strings), never empty; every kind dispatches to an owner whose contract is
bounded + idempotent + ends in repaired-or-stronger-rung; totality enforced
by a matrix CI test (synthesize each fault kind on a fixture progress.kv —
including the exact live 3166989 shape as a pinned regression — and assert
H\* climbs or a durable rung-3 refold request is armed) + a lint gate (kind
strings minted only in `stall_kind.h`; every `blocker_set` site names an
owner or registered escape).

**With LCC in place, a pinned H\* has exactly five causes, each owned:**
(a) genuine consensus reject → named PERMANENT halt, by design (parity);
(b) disk/resource → existing typed blocker; (c) network starvation at
body_fetch → peer machinery; (d) any stored-row-vs-fold divergence including
corruption → `stage_rederive_range` at H\*+1 (the blocker escape);
(e) primitive refusal (missing inverse-delta) → arm refold-from-anchor via
the existing durable-request pattern + self-respawn via the existing
`/proc/self/exe` path so the armed deep rung actually executes. The 7-rung
stub escalator collapses to **3 implemented rungs: rederive → restart with
refold armed → page** — every rung real, bounded, auto-terminating.

## 1. The design in one sentence

**One law, one ladder, one default owner:** if the header frontier is ahead
and H\* has not advanced for T, a single watchdog fires a universal,
rung-escalating repair ladder at the named blocker height; rung 1 re-derives
everything at h from the canonical body with no knowledge of the birth
mechanism; rungs strictly strengthen; the final rung (restore a locally
produced complete-state recovery seal and refold) is separately copy-proven — so
class-specific healers become fast-path optimizations, never correctness
requirements.

### The progress law

```
INVARIANT (H*-progress): header_frontier > H*  ∧  H* unchanged for T
    ⇒ the universal ladder is actively executing a rung at blocker(H*+1),
      and each unwitnessed rung hands off to a strictly stronger rung
      within its bounded time budget. Witness for EVERY rung = H* > h.
```

L0 already always names `blocker(H*+1)` — that part is correct and stays.
The response becomes total *by construction* instead of total by enumeration.

### The universal ladder (default owner for EVERY blocker kind)

- **Rung 0 — class fast-path.** Existing conditions, ≤2 attempts. Optional.
- **Rung 1 — single-height re-derivation (the universal repair).** For
  blocker at h, in ONE transaction: delete every stage row at h for stages ≥
  body_fetch (ALL hashes — canonical and residue), rewind those cursors to
  h−1, mark the canonical body (hash from the PoW-proven header chain) for
  refetch if unreadable, let the normal stage drives re-run. Idempotent,
  bounded, mechanism-agnostic. Implementation seed: generalize the existing
  one-shot `stale_script_replay_tx` (already deletes stale script+proof rows
  and re-runs one body) to be stage-general, all-hashes-at-h, rowless-hole-
  capable, and **domain-unrestricted** (kills the refill/replay gap).
  Coins safety: h > coins contiguous-ok frontier by definition of blocker(H\*+1)
  when utxo_apply is the blocked stage; when the hole is BELOW
  coins_applied_height (the live case — coins writer ran ahead), rung 1
  re-derives script/proof verdicts only and never touches coins (verdict
  re-derivation is pure; `DEFENSIVE` rule: same validation code, no skips).
- **Rung 2 — window re-derivation.** Rung 1 over [h−K, h] (K ≈ seal grid,
  1000). Catches multi-height residue/contamination, and re-verifies the
  seal at the window base (catches D4's silent coins divergence).
- **Rung 3 — refold from the newest verified rolling anchor ≤ h.** Reset
  coins to the anchor set, purge stage logs above it, refold forward.
  Bounded by anchor cadence. Preconditions maintained continuously (§3).
- **There is no rung 4.** If disk/peers are truly gone, the node emits a
  typed RESOURCE/DEPENDENCY blocker with syscall/peer evidence — an honest
  named external halt, not a stuck internal state.

Rules: every rung bounded in time; unwitnessed ⇒ next rung automatically;
every transition emits an event AND a typed-registry blocker (`z23 core sync blockers`
can never again show 0 during a stall); ladder state is durable (crash mid-
rung resumes at the same rung, idempotent by design).

### Why this ends the whack-a-mole

Rung 1 repairs *state at h from first principles* (canonical body +
re-execution) without knowing the birth mechanism; rung 3 repairs *anything
below h* the same way. New birth mechanisms are auto-cured on day 0;
recurring ones earn a rung-0 fast path for latency only.

## 2. Framework fixes (small, immediate — D2/D3)

- **F1 Kill the zombie** (`condition.c`): while `currently_active`, remedy
  cadence continues on backoff regardless of detect() flapping; an episode
  ends ONLY via witness-clear. detect() gates episode START, never
  CONTINUATION.
- **F2 Page + escalate on AGE, not attempts**: `active_for > age_budget` ⇒
  operator page AND hand-off to the ladder, even at attempts=1.
- **F3 Frontier ⇒ typed blocker registry, always**: `hstar_next_blocked`
  registers a typed blocker whose escape action IS the ladder;
  `repair_owner` defaults to `universal_ladder`, never `""`.
- **F4 Totality gate (CI)**: test walks every emittable (kind × stage ×
  reason) and asserts non-empty owner (trivial once F3 lands) + lint gate
  banning `JOB_IDLE`-waiting-on-a-healer without a registered ladder binding,
  and banning any purge/repair that deletes rows without either rewinding
  cursors or holding a registered filler for the exact domain it creates.
- **F5 H\*-progress watchdog**: supervisor child `chain.hstar_progress` whose
  progress marker IS H\*; stall ⇒ fire ladder. Replaces the stub escalator's
  arming logic (which today only triggers off conditions that detected —
  the exact thing that fails, `sticky_escalator.c:258-266`).
- **F6 Peer-gate fix**: `peer_lag_allows_repair` compares against H\*, not
  the header tip (`reconcile_light.c:56-74`).

## 3. Rung-3 preconditions become continuous duties (D5, sovereign cure)

- **Seal ring → real rolling anchors.** The write side already co-commits
  (block_hash, coins_sha3, count, supply) per 1000 blocks inside the
  utxo_apply txn and ratifies at finality depth. Add: (a) retain a local
  coins snapshot at every Mth seal grid point (M×1000 blocks; prune older),
  SHA3-bound to the ratified seal; (b) implement the seal window_rebuild
  consumer; (c) `-refold-from-anchor` generalizes from the one compiled
  height to "newest verified anchor ≤ h", runtime-invocable (not boot-only).
- **Continuous seal verify** (background duty): recompute coins_sha3 over the
  window at each ratification; a mismatch fires the ladder at the window —
  this converts D4's silent coins divergence from undetectable to bounded.
- **Close the remaining hole factories** (subtraction): purge_noncanonical
  rewinds cursors for what it deletes (or is deleted in favor of rung 1);
  boot clamp `stage_reconcile_clamp_tip_finalize_to_floor` and the
  seed-exempt span become unnecessary once the sovereign anchor replaces the
  borrowed seed (in-flight, `self-verified-tip-plan.md` Act 3) — delete them.
- Crash-atomicity is already sound (rows+cursor per txn, `stage.c:420-476`;
  drain batches `job.h:56-81`) — keep it gated so it stays true.

## 4. Execution order (each copy-proven before live; H\* CLIMB is the gate)

0. **Live-cure the instance by its class** (S/M): (a) add the rowless-hole
   detector to the stale-script replay (`reducer_frontier_replay.c:68-136`
   detectors all require an EXISTING row; add "row ABSENT below cursor" as a
   fourth match routing to the SAME `stale_script_replay_tx`), (b) purge
   co-commits cursor rewind in one BEGIN IMMEDIATE (`purge.c:105-268`),
   (c) F6 peer-gate compares H\* not header tip / bypasses for local
   re-derivation (`reconcile_light.c:56-74,240-263`). The body at 3166989 IS
   persisted (contiguous body frontier 3167047). Copy-prove on a copy of the
   live stalled datadir, watch H\* climb past 3166989, deploy.
1. **F1+F2 condition-engine zombie + age-paging** (S) — cures the meta-defect.
2. **F3+F5 kind-keyed owner (never "") + H\*-progress watchdog** wired to
   `stage_rederive_range` + typed-blocker mint on persistent frontier
   blockers (M).
3. **LCC write rules + deletions** (M): seed_exempt out, boot force-raise
   through the cap, `ZCL_REPLAY_COUNT_ONLY` deleted, force_stage_cursor
   lower-only, post-commit first-gap assertion + cursor-write lint gate.
4. **F4 totality matrix test** (L): synthesize every stall kind on a fixture,
   assert H\* climbs or rung-3 arms; pin the 3166989 shape as regression.
5. **Rung 3 real** (L): seal-grid snapshot retention + `window_rebuild`
   consumer + runtime refold-from-newest-anchor + self-respawn so an armed
   refold executes without a human (the anchor mint at 3,056,758 currently
   running is the first sovereign base of this ladder).
6. **Subtraction pass** (M): delete the refill layer + tear/peer gates for
   internal repairs + 4 stub escalator rungs + `diagnostic_repair_hint`
   string table (kind-keyed now); demote bespoke conditions to rung-0;
   delete the borrowed-seed loader once rung 3 is live.

## 4a. The two-boot heal defect class — P6 + P7

A sixth defect class, distinct from D1-D5: **the boot restore can leave the
node DEGRADED for a whole process lifetime while its own repairs are already
on disk — the heal lands on the NEXT boot, not the current one.** Root cause:
a corrupt flat block-index tip reloads as a contentless stub; the ancestry
rebuild heals the stub's content in place and fills the active-chain array,
but nothing raises `active_chain`'s tracked height afterward, so lookups at
the tip stay bounded by the stale (pre-heal) height and the integrity check
reports a phantom hole — DEGRADED_SERVING for the rest of that process
lifetime. The repair only takes effect because it was persisted to disk and
loaded clean on the *next* boot — exactly the failure mode this document
exists to kill.

Fixes (both container-only derived state, zero consensus surface):

- **P6** `chain_restore_repair.c` — the install guard now compares CONTAINER
  truth (`active_chain_cached_tip(c) != tip || c->height != tip_h`), and a
  new `chain_restore_publish_rebuilt_tip()` raises c->height after any full
  rebuild (`populated == tip_h+1`), using the slot entry the rebuild actually
  placed (which may be the disk-verified replacement).
- **P7** `block_index_loader_topup.c` — a height conflict against a
  contentless stub (nBits=0 ∧ no HAVE_DATA ∧ nTx=0) hydrates the stub from
  the projection row (tracked like an insert: pprev-link + chainwork pass
  cover it); genuine label conflicts (loaded entry has real content) still
  refuse loudly.

## 4a-bis. P8, P9, and the raise-only correction

Four more defects, adversarially confirmed and fixed:

- **P6 correction (raise-only)** — `chain_restore_finalize` is NOT boot-only
  (it is the `chain_integrity_failed` runtime remedy,
  `chain_integrity_failed.c:67`), and at runtime `c->height` legitimately
  runs up to 8192 ABOVE the finalized tip (the lookahead window). The first
  container guard (`c->height != tip_h`) would have fired there and
  install_tip_slot would have SHRUNK the window mid-tick. Both the guard and
  `chain_restore_publish_rebuilt_tip` are now raise-only: they act only when
  the container is BEHIND the tip (or the exact tip slot is wrong), never
  when it is ahead.
- **P7 correction (descendant chainwork)** — a hydrated stub had
  nChainWork==0 while detached, so PRE-EXISTING flat-loaded children above
  it carry work collapsed through the zero; nothing recomputed them, pinning
  best_header at the hydrated block (the pinned-best_header stall class,
  a re-introduced two-boot heal for the work field). `topup` now re-runs the
  canonical `block_index_forward_pass` over the whole map whenever
  `stubs_hydrated > 0`.
- **P8 (stub launderer)** — the corrupt-flat "quarantine" (`boot.c:1729-1776`)
  only set `loaded=false`; the LevelDB fallback find-or-inserted ON TOP of
  the 3.1M stale flat entries and the mid-boot save re-persisted the corrupt
  UNION every boot — how the height-0 stub survived across generations
  (proof: "3168944 entries in 2s" is impossible for a real LevelDB load).
  Fixed by subtraction: the mid-boot re-save is skipped when the flat was
  declared corrupt (`flat_union_tainted`); the shutdown save persists the
  HEALED map. Full clear-before-fallback deferred (block_map_free leaks
  arena entries by design; needs its own copy-prove).
- **P9 (reindex budget burn → TERMINAL poison)** — the attack phase's only
  two confirmed attacks, both the same defect: the escalator's reindex rung
  called `boot_auto_reindex_request` on EVERY dispatch (5s self-heal
  cadence), burning the 3-attempt CROSS-BOOT budget to TERMINAL in ~15s with
  zero actual reindexes, and the TERMINAL marker was never auto-cleared
  (`chain_restore_repair.c` gated the clear on `pending()`, false for
  terminal) — permanently poisoning the only rebuild-from-blocks path
  (`boot_crashonly.c:19` skips consume forever). Fixed: (a) both runtime
  requesters (`sticky_escalator.c` reindex rung, `stage_db_fault.c`) hold
  while a request is pending instead of re-incrementing — the budget now
  counts BOOTS, not ticks; (b) a clean post-restore boot clears the terminal
  marker too (the node is provably healthy, the marker describes a state
  that no longer exists).

Everything else the adversaries tried was refuted by an existing layer:
reorg-spam lands in the explicitly-permitted growing-gap + ladder branch;
SQLITE_BUSY storms are impossible in-process (single progress.kv connection
behind a recursive mutex); the operator_needed-latch chain was caught.

## 5. What this deliberately does NOT change

- The fold's refusal to advance past an unproven height (consensus safety).
- Consensus parity: rungs re-execute the SAME validation code — never skip,
  never force-accept.
- One authority: rungs repair stage logs/coins from locally validated bodies +
  explicit trust-state anchors; no projection, peer claim, or heuristic ever
  gates or rolls back the fold
  (the commitment-audit lesson, kept).

## 6. Observability debts found during diagnosis (fix alongside)

- `z23 dbquery` cannot reach `*_log` tables (progress.kv, not node.db) — attach
  progress.kv read-only or add a typed read surface.
- `legacy_mirror` WARN-spams thousands of identical lines while zclassicd
  resyncs (RPC −28) — throttle to transitions + periodic keep-alive.
- zclassicd (C++ reference) is itself at height 0 activating best chain;
  until it recovers, oracle-coupled repairs (header backfill hardwired to
  127.0.0.1:8232) have no oracle — another reason repairs must be
  self-contained (P2P/bodies), which the ladder is.
