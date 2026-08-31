# Never-stuck foundation — retained design record

> **STATUS: the wedge this doc diagnoses is CURED** — the serve node is AT
> NETWORK TIP on self-verified state (`docs/HANDOFF.md` §0-LATEST), via the
> checkpoint-content consensus-bundle install path, NOT via this doc's
> literal "self-mint a from-genesis SHA3 anchor → `-refold-from-anchor`
> cutover → DELETE the borrowed loader" sequence (that sequence is still
> undone in code — see `self-verified-tip-plan.md`'s top-of-file note).
> Verify current live state fresh via `z23 status` /
> `z23 dumpstate reducer_frontier`; this file is retained as a design
> record for the never-stuck hardening map + the per-height UTXO-ladder gap,
> not as an open cure plan. The authoritative gates are in
> `SOVEREIGN-NETWORK-ROADMAP.md`.

## 1. Thesis

Wire the self-sufficient proof (`snapshot_verify`) into the cold-import door, kill
the row-count heuristic and the cursor-stamp lie so every stage cursor is *derived*
from a folded log instead of *installed*, then delete ~13,500–15,500 LOC of
repair / trust-brain / mirror accretion that exists only to cover for an unproven
foundation. Fast + never-lies + never-stuck become the *same* property — the node
only ever records facts it computed.

## 1b. The principle — fold the frozen part ONCE, then verify/locate/repair cheap

The mental model future agents must internalize (it makes the cure both fast AND
correct, and it is *why* replaying the chain is the lazy solve):

The chain is **immutable below `tip − ZCL_FINALITY_DEPTH` (=10)** —
`zcl_immutable_height()` (`sync_evidence_policy.c:11`); reorgs deeper than 10 are
refused `below_finality_depth` (IBD relaxes to 1000). Information theory on that: a
fact over the frozen part **never changes**, so compute its fingerprint **once** and
thereafter **verify by O(1) comparison, locate any divergence by O(log n) bisect,
repair only the bounded mutable window.** Work is proportional to the ~10-block tip
window + log(n) hash checks — **never the chain.** Replaying genesis→tip (or even
checkpoint→tip) to *check* or *fix* state is recomputing frozen facts: the slow solve.

**Keystone diagnosis — the node fingerprints the WRONG thing per height.**
It commits to AND checks a per-height
**block hash** — `validate_headers_log.hash`, `script_validate_log.block_hash`, and
`reducer_frontier.c:422` (`apply_hash_agreement`) already bisects the first block-hash
split. But **no folded log stores a per-height UTXO-set fingerprint** — `utxo_apply_log`
holds only `spent/added_count` + `total_value_delta`; `tip_finalize_log` holds
`utxo_size_after` (a COUNT, not a hash). So a divergence that is **height-correct (block
hash agrees) but state-wrong (a wrong-fork coin)** is **invisible to every per-height
check** — this class of fault (a wrong-fork coinbase where the block hash is
correct) is exactly what a past wedge exhibited. You cannot bisect or
bounded-repair a fault you never fingerprint.

**The pieces already exist — compose them, don't rebuild:**
- Finality window: `ZCL_FINALITY_DEPTH 10` (`main_constants.h:33`), `zcl_immutable_height` (`sync_evidence_policy.c:11`).
- ONE canonical (script-inclusive, zclassicd-verified) SHA3 UTXO fingerprint, single rung: `checkpoints.c:86` (h=3,056,758); the runtime stamp is a single `node_state 'utxo_sha3'` (INSERT OR REPLACE — at most one stored).
- The correctly-shaped per-100-block ladder is **DEFINED but DEAD**: the Commitment MMR, leaf `{height, block_hash, utxo_root, data_root}` (`mmr.h:120,122-126`), appended by `rpc_blockchain_maybe_commit` (`blockchain_controller.c:243`) — which has **zero callers on the connect path** (`tip_finalize_post_step.c:184-197` appends only the block-hash MMR + the MMB header leaf), so the ladder is never populated. Its `utxo_root` is the **XOR accumulator** (`blockchain_controller.c:266`), which omits scriptPubKey → **not byte-comparable** to the canonical SHA3.
- MMB/FlyClient proves sampled header work, while the current auxiliary leaf
  also carries `utxo_root`. ZClassic headers do **not** commit that field or the
  MMB root, so it remains a peer assertion rather than a PoW state binding.
- A working **binary-search locator** already exists (`mirror_divergence_locator.c:168-193`) — but it bisects against the **external zclassicd** over block hashes, not a self-committed ladder, not UTXO state.
- Bounded-window **repair** already clamps to `tip−10` (`utxo_apply_delta_reorg.c`).

**Corrected composition:** on the connect path, fold each finalized block once and
record a per-height locally derived canonical UTXO fingerprint for diagnosis and
same-node restoration. An auxiliary Commitment MMR can make that ladder tamper-
evident within the node's own evidence chain, but it is not a ZClassic header
commitment and cannot authenticate peer state. Point local bisect/restore at this
ladder and keep assisted snapshots in assisted trust until full-history promotion;
trigger the existing bounded-window repair.
Then verify/locate/repair are **self-contained and O(log n + window)** — fast,
never-lies, never-stuck, the same property.

## 1c. Why fold-from-bodies is the only certainty

**Certainty does NOT come from copying the LevelDB carefully — it comes from
verifying any candidate UTXO set against a fingerprint computed from our own
immutable block bodies.** The copy can be arbitrarily messy; it is accepted
only if its whole-set SHA3 equals the body-derived SHA3 at a pinned height,
else it is rejected and the set is folded from blocks. This covers the full
blast radius of LevelDB copy corruption (keyspace-wide).

A live `cp -a` over a running daemon can be silently wrong in several ways —
a missing referenced SST, mismatched SST/MANIFEST versions, a torn MANIFEST
or `.log` tail, a swallowed mid-iteration CRC error
(`node_db_import_service.c:380` currently discards `db_iter_check_error`'s
result), a fork-tip image (internally consistent but naming a block later
disconnected), or a stale-but-clean image — most of these are SILENT and
several are keyspace-wide, so a "reconcile the top 10 blocks" repair cannot
find them; only a whole-set commitment can.

**Do we even need the copy? No — not for correctness, only for speed.**
Block bodies + the one bit-for-bit-verified SHA3 anchor (h=3,056,758, count
1,354,769, root `5817f0ec…`) deterministically reconstruct the entire UTXO
set with zero zclassicd dependency. The copy buys only skipping the fold of
~94,654 blocks (anchor→tip). **If the from-blocks fold is fast enough, delete
the copy mechanism entirely.**

Falsification tests that must pass before deleting the cp path: a
fork-coin fixture MUST report a SHA3 mismatch and refuse; a clean image MUST
match and accept (resolve txid byte-order: is our stored txid BLOB the same
internal order as zclassicd's uint256 LevelDB key?); body fold
genesis→3,056,758 MUST reproduce SHA3 `5817f0ec…` / count 1,354,769; a
one-byte-corrupted SST MUST hard-halt the import
(`node_db_import_service.c:380` wired to abort on any iterator error);
full-history replay against the real chain — zero false-rejects across
3.15M blocks (h=478544 doctrine); confirm `utxo_apply_delta_reorg.c` refuses
unwinds deeper than `ZCL_FINALITY_DEPTH=10` at `in_ibd=false`.

## 2. Invariants (true by construction)

- **I1** No coin enters sovereign state except by `utxo_apply` folding verified
  blocks or by atomically restoring a locally self-minted complete-state seal with
  its applicable proof manifest. Peer/release snapshots remain explicitly assisted;
  height/hash matching never promotes their contents. No row-count acceptance.
  *Lint* `check-no-rowcount-install`; *test* `test_cold_import_requires_proof`.
- **I2** No stage cursor stamped forward without a real per-stage log row. Delete the
  `seed_exempt` bypass. *Lint* `check-no-seed-exempt-stamp`; assert H*==MIN(real cursors).
- **I3** H* is derived, never installed — `reducer_frontier.c` stays the only authority,
  refuses + names the missing height. (Already true — protect it.)
- **I4** Logs append-only, keyed `(height, block_hash)`, readers pick the active-hash row.
  *Lint* forbid `INSERT OR REPLACE` on the 7 stage logs; `test_log_append_only_reorg`.
- **I5** Consensus parity inviolable — a canonical block is NEVER marked invalid; every
  predicate tightening replayed against real history first (h=478544 lesson). E13 + goldens.
- **I6** Node stands alone — zero runtime dependence on zclassicd. *Lint* `check-no-zclassicd-runtime`.

## 3. The build (ordered, each copy-proven + replayed before live)

- **B1 — An auxiliary root does not bind UTXO state to PoW.** The MMB leaf is
  `block_hash||height||timestamp||nBits||sapling_root||chain_work` (`mmb.h:10`)
  — **no UTXO commitment** — and `chain_work`/`nBits` are attacker-chosen.
  SHA3 only proves bytes hash to the root the *peer claimed*. Because ZClassic
  headers commit no UTXO root, adding one to a peer-built auxiliary proof does
  not close that gap. Keep peer/release snapshots explicitly assisted and
  promote only after local full-history verification; never change consensus
  first. **This gates everything below.**
- **B2 — Assisted-only FlyClient gate.** It may authenticate advertised header
  work and manifest integrity, but cannot promote snapshot state to sovereign.
- **B3 — Delete the row-count heuristic (`utxo_recovery_restore.c:323`) + the `seed_exempt`
  stamp (`stage_anchor.c:257`).** Delete only after the atomic complete-state
  installer and background sovereignty promotion replace it.
- **B4 — Logs truly append-only / reorg-correct** — re-key the 7 stage logs to
  `(height, block_hash)`, readers select active-hash. Schema change touching consensus reads
  → replay real reorg history first. MEDIUM-HIGH risk.
- **B5 — Confirm fold is cheap** — still UNMEASURED, and **cannot be measured
  with any existing verb**: `rebuild_recent 3056758` is invalid on two
  grounds — it caps at 10,000 blocks (`REBUILD_RECENT_MAX_RANGE`) and fetches
  every block from zclassicd RPC. `-reindex-chainstate` replays from GENESIS
  and self-refuses on a cold-import datadir (no genesis-side bodies).
  `poison_rewind` is frontier-only + ok=1-floor-guarded, so it can't target
  the checkpoint. The forward fold engine over on-disk bodies EXISTS
  (`body_fetch`→`utxo_apply`, network-free) but there is **no operator verb
  to rewind utxo_apply to a chosen height and re-drain forward**. So B5 *is*
  B2: the measurement and the fix are the same work — once the
  snapshot-seed-then-fold trigger lands, it measures itself. Don't assume
  "coinbase-only / <1 min": `script_validate_log` + `proof_validate_log`
  have ZERO gap rows, so the fold re-runs full script+proof validation for
  real blocks with high `vin` counts. Parallelize `script_validate` only if
  the first real measurement demands.
- **B6 — Honest cold readiness = verify assisted bundle integrity → install
  at an exact validated chain location → fold to tip (B5).** Keep the trust
  posture assisted until independent full-history promotion. No zclassicd
  runtime dependency. Must beat MVP C3 (<10 min) without calling it sovereign.
- **B7 — Honest recovery from a FORWARD false-reject (a second wedge root).**
  The historical wedge was not single-rooted: one structural pin (H* honestly
  refusing a non-contiguous log) has TWO independent causes — the
  borrowed-import hole (B1–B3) AND a genuine forward false-reject:
  `script_validate`/`proof_validate` write an `ok=0` row and STILL advance
  their cursor, pinning H* with **no in-stage auto-recheck** (grep for
  recheck/quorum in those stages = empty). The ONLY things that clear an
  `ok=0` today are the operator `reconsiderblock` path and the very
  `stage_repair` ladder slated for deletion. Build a sound, non-lie-cover way
  for an `ok=0` to be re-derived and (on genuine validity) cleared — e.g.
  re-run the predicate at a parity-checked height with a peer-quorum
  witness. **Gates the D5 repair-ladder deletion** (deleting it without B7
  removes the only escape from a forward false-reject). Pairs with the two
  known latent parity holes (the all-zeros-only `hashFinalSaplingRoot`
  reject `connect_block.c:638`; the h=478544 tx-size lesson). Verify still
  applicable before acting — re-grep the cited call sites.
- **B8 — Demote the `oracle_policy` halt path to evidence-only (a
  never-stuck risk).** It IS production-wired, not just telemetry. Feeders
  `oracle_policy_record_disagreement()` fire from the four zclassicd
  comparators (`quorum_oracle_service.c:334`,
  `mirror_divergence_locator.c:282`, `legacy_mirror_sync_service.c:274/303`,
  `zclassicd_oracle_service.c:203`); enough distinct disagreement heights →
  `OP_HALTED` (`oracle_policy.c:168`) →
  `oracle_policy_chain_extension_allowed()` returns false (`:205`) →
  consumed at `rolling_anchor_service.c:403,433`. So a zclassicd that is
  merely WRONG/behind can stop the rolling-anchor extension — a comparator
  gating liveness, against the "stands alone / cannot get stuck" property.
  (Open trace: confirm the exact blast radius — whole-chain advance vs only
  the rolling-anchor service — before the cut.) Fix = record divergence as
  evidence, never gate extension on it. Low risk, high principle. Verify
  still applicable before acting — re-grep the cited call sites.

## 4. The deletions (LAST, each gated on its replacement)

Net **~13,500–15,500 LOC** removed, zero features lost. Bottom-up:

| Order | Cluster | LOC | Gated on | Preserve |
|------|---------|-----|----------|----------|
| D1 | coin_backfill | ~4,400 | B3 | torn-import verdict folded into a transition check |
| D2 | legacy_mirror + zclassicd_oracle + quorum/policy/divergence | ~4,600 | I6/B6 | `chain_linkage` fork-HOLD KEPT; oracle reads stubbed |
| D3 | utxo_parity vs zclassicd + parity_poll | ~1,300 | I6 | C8 parity canary re-sourced to peer quorum |
| D4 | cold-import LDB cluster | ~3,500 | B2+B3 | KEEP frontier_gate, projection_topup, importblockindex header read, snapshot_apply, reindex_epilogue |
| D5 | reducer_frontier reconcile ladder | ~3,700 | B3+B4 | KEEP rewind (reorg), body_fetch, header_solution, boot clamp |
| D6 | stage_anchor seed_exempt + condition siblings | ~800 | B3,D2 | all reorg/disk/peer conditions preserved |
| D7 | purge verb | ~340 | **B4 ONLY** | reorg-residue now structural |

**Ordering rule:** D7 is LAST and strictly gated on B4 — it is currently the only thing
keeping the height-keyed logs reorg-correct.

## 5. Scale / many-eyes

Lighter-model fan-out: per-file deletions + include/registry/boot-spec edits, condition
de-registration, `INSERT OR REPLACE`→`INSERT` sweeps, the new grep lint gates.
Senior care: assisted-trust boundaries, B4 (active-hash reader), B2/B3 (the flip), every
real-history replay, D2's fork-HOLD stub edits.

## 6. Honest residuals (measure before irreversible cuts)

1. **Fold wall-clock is estimated, not measured — AND not measurable today.**
   No existing verb re-folds utxo_apply from the checkpoint over on-disk
   bodies (`rebuild_recent` caps at 10k + needs zclassicd;
   `-reindex-chainstate` is genesis-wide + self-refuses on a cold-import
   datadir; `poison_rewind` is frontier-only). The fold rate can only be
   measured *after* the B2 from-checkpoint fold trigger exists — resolve
   this residual *inside* B2/B5, not before D1. On-disk UNDO is also missing
   for the top of history (present only checkpoint..~3,137,000 as last
   surveyed), so a forward re-fold (bodies-only) is the viable path;
   rewind-from-undo is not.
2. **B1's proposed PoW binding is impossible above current ZClassic consensus.**
   Keep auxiliary UTXO commitments as advisory evidence and use explicit
   assisted trust plus local full-history promotion; never change consensus first.
3. **Restart-durability after cold re-import** is a separate root cause; confirm whether B6
   inherently fixes it.
4. **`utxo_mirror_sync` (node.db utxos)** — KEEP pending proof it's a pure rebuildable cache.
5. **`state_window_inconsistent`** — decide at D6, may be reusable for commitment-audit.
6. **B4 migration cost** on `progress.kv`/`node.db` — measure on a copy before committing.
