/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_history_import_service — COMPLETE, ATOMIC historical anchor +
 * nullifier import from an operator's zclassicd chainstate LevelDB.
 *
 * WHY: a snapshot/seed datadir holds only the CURRENT shielded frontier, so
 * every historical Sprout/Sapling anchor root and every historical nullifier
 * below the reducer cursor is absent. anchor_kv/nullifier_kv fail those lookups
 * CLOSED (HISTORY_INCOMPLETE) while their activation cursors are positive, which
 * pins H* at the wedge height (utxo_apply.anchor_backfill_gap +
 * utxo_apply.nullifier_backfill_gap). zclassicd's tip chainstate DOES persist
 * the complete active-chain set (additive-only, never pruned forward). This
 * service imports that complete set — both pools, full history — and flips BOTH
 * activation cursors to 0, in ONE transaction.
 *
 * CONSENSUS-CRITICAL / ALL-OR-NOTHING: flipping a cursor to 0 converts a SAFE
 * halt (missing root = HISTORY_INCOMPLETE, block held) into an ACCEPT (missing
 * root = MISSING, block false-rejected → re-wedge / fork). Therefore the import
 * is atomic: ANY read/deserialize/verify/write anomaly rolls the WHOLE
 * transaction back and leaves both cursors POSITIVE (the safe wedge intact).
 * The cursors flip only after the complete set committed and the tip Sapling
 * frontier root was bound to the block header's hashFinalSaplingRoot.
 *
 * This is an owner-gated, copy-prove-gated path (never auto-run on a live
 * datadir) — see engine/entry/main.c -import-complete-shielded and §6 of
 * docs/work/shielded-history-importer.md.
 */
#ifndef ZCL_SERVICES_SHIELDED_HISTORY_IMPORT_SERVICE_H
#define ZCL_SERVICES_SHIELDED_HISTORY_IMPORT_SERVICE_H

#include "core/uint256.h"

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* progress_meta key the importer stamps its provenance row under (source,
 * best block, per-pool counts, tip-anchor-bind result, self_folded=false) on
 * a successful commit — see shi_write_provenance in
 * shielded_history_import_service.c §4.4/§5 of
 * docs/work/shielded-history-importer.md. Exposed here so other
 * SELECT-only readers (sovereignty_dump_state_json) can read it back via
 * progress_meta_get without duplicating the literal. */
#define SHIELDED_IMPORT_PROVENANCE_KEY "shielded_import.provenance"

/* Per-run outcome. Populated on both success and refusal (partial counts on a
 * refusal reflect what was iterated before the anomaly; nothing was committed
 * unless `committed` is true). */
struct shielded_import_report {
    int64_t sapling_anchors;     /* verified Sapling anchor rows imported */
    int64_t sprout_anchors;      /* verified Sprout anchor rows imported */
    int64_t sapling_nullifiers;  /* Sapling nullifiers imported */
    int64_t sprout_nullifiers;   /* Sprout nullifiers imported */
    int64_t anchor_boundary;     /* positive anchor cursor value before the flip */
    int64_t nullifier_boundary;  /* positive nullifier cursor value before the flip */
    bool tip_anchor_bound;       /* best Sapling root == expected tip header root */
    bool committed;              /* true iff the atomic transaction COMMITted */
};

/* ── Live progress (never-silent invariant) ───────────────────────────────
 *
 * The import streams millions of anchor + nullifier records inside ONE
 * transaction. That work is CPU-bound and, historically, silent — a violation
 * of the node's prime invariant (a stall must always be a NAMED point at a
 * known cursor, never a quiet stop). The service therefore maintains lock-free
 * atomic progress counters + a coarse phase, periodically emits a
 * "shielded import progress: ..." node.log line, and exposes a snapshot getter
 * a concurrent diagnostics reader (dumpstate on another thread) can render
 * without touching the database. */
enum shi_phase {
    SHI_PHASE_IDLE            = 0, /* no import has run in this process yet */
    SHI_PHASE_SNAPSHOT        = 1, /* opening the chainstate snapshot + tip bind */
    SHI_PHASE_SCAN_ANCHORS    = 2, /* streaming Sprout+Sapling anchor frontiers */
    SHI_PHASE_SCAN_NULLIFIERS = 3, /* streaming Sprout+Sapling nullifiers */
    SHI_PHASE_BIND            = 4, /* flipping activation cursors + provenance in-tx */
    SHI_PHASE_COMMIT          = 5, /* COMMITting the atomic transaction */
    SHI_PHASE_DONE            = 6, /* last import finished (committed OR rolled back) */
};

struct shi_progress {
    bool    active;          /* an import is currently running */
    int     phase;           /* enum shi_phase (last observed) */
    int64_t anchors_done;    /* anchor rows streamed so far (both pools, cumulative) */
    int64_t nullifiers_done; /* nullifier rows streamed so far (both pools, cumulative) */
    int64_t elapsed_ms;      /* since the current/last import began (frozen once done) */
};

/* Snapshot the importer's live progress for a concurrent reader (e.g. a
 * dumpstate handler on another thread). Reentrant + lock-free (atomic loads);
 * never touches the database or the chainstate. Always fills *out; returns
 * false only on a NULL argument. */
bool shielded_history_import_progress_snapshot(struct shi_progress *out);

/* Import the COMPLETE historical Sprout+Sapling anchor and nullifier sets from
 * a point-in-time copy / fixture of a zclassicd chainstate LevelDB at
 * `chainstate_src_path` into anchor_kv + nullifier_kv held in `progress_db`,
 * atomically, then flip both activation cursors to 0.
 *
 * `expected_tip_block_hash` and `expected_tip_sapling_root` are the target
 * header identity at `expected_tip_height` (the chain-committed bind, §3).
 * The source chainstate's best-block pointer MUST equal the target block hash;
 * otherwise its additive nullifier set may include spends above the target
 * resume point and the import refuses before opening its transaction. The
 * matching Sapling anchor MUST also be present and hash to the expected root.
 *
 * All-or-nothing: on ANY anomaly (torn record, deserialize/root mismatch,
 * tip-frontier bind failure, empty required pool, non-positive/unequal cursors,
 * or any write error) it ROLLS BACK, writes NOTHING, leaves both cursors
 * POSITIVE (safe wedge) and returns false. Returns true only when the complete
 * set committed and both cursors are durably zero. `out` may be NULL. */
bool shielded_history_import_from_chainstate(
    struct sqlite3 *progress_db,
    const char *chainstate_src_path,
    int64_t expected_tip_height,
    const struct uint256 *expected_tip_block_hash,
    const struct uint256 *expected_tip_sapling_root,
    struct shielded_import_report *out);

/* ── target-height guard (fail-closed) ────────────────────────────────────
 *
 * The reducer's fold resumes at the TARGET datadir's coins authority
 * (fold_resume = coins_applied_height, so the imported frontier must BE the
 * tree state at fold_resume - 1 == the coins island root). This probe verifies
 * that the caller selected that target height. The import service separately
 * requires the SOURCE chainstate's persisted best-block hash to equal the
 * exact target header at that height; that second bind prevents an additive,
 * unheighted nullifier set from including future spends.
 *
 * This probe is the ONE shared predicate, implemented in
 * engine/services/src/shielded_history_import_bind_guard.c: the
 * -import-complete-shielded verb (engine/entry/main.c) calls it for a terminal-visible
 * refusal with BOTH heights + the remedy, and
 * shielded_history_import_from_chainstate calls it again before opening its
 * transaction (defense in depth — a caller bypassing the verb cannot select a
 * different target height). Returns true when the import may proceed;
 * false on a mismatch (*coins_best_out receives the island root, or -1 when
 * the refusal is a progress.kv read error). */
bool shielded_history_import_bind_guard_probe(
    struct sqlite3 *progress_db, int64_t tip_height, int32_t *coins_best_out);

struct node_db;

/* Register the CURED coins tip (coins_applied_height - 1) as a cold-import
 * TRUST anchor so Invariant A (utxo_recovery_block_ancestry_break) installs it
 * into the in-memory active chain instead of refusing it as a detached island.
 *
 * WHY: clearing the shielded anchor/nullifier wedge lets utxo_apply resume, but
 * the coins tip left by the transparent seed has a pprev height-tear between the
 * compiled SHA3 anchor and it. Without a trust anchor at the tip, the boot
 * restore's Invariant A gate refuses to install it, active_chain_tip() stays
 * NULL, and process_headers builds a genesis-only getheaders locator — the tail
 * bodies to network tip are never requested.
 *
 * The anchor identity is the import's OWN header-committed coins-best — height
 * from progress.kv's co-committed coins_applied_height, hash from the
 * validate_headers_log own-hash (the Invariant A trust root) via
 * reducer_frontier_derive_coins_best — never a borrowed peer value (respects
 * check-no-new-borrowed-seed). Registers the in-memory anchor (effective this
 * process, e.g. the copy-prove harness / unit test) AND writes the DURABLE
 * node_db seed keys the boot restore path re-reads every boot, so the coins tip
 * installs on the next NORMAL boot after the owner-gated import mode exits.
 *
 * Call AFTER a successful shielded_history_import_from_chainstate, with the same
 * progress_db (must be progress_store_db() so the durable count token reads the
 * canonical store) and an open node_db for the target datadir. Best-effort:
 * returns false (logs the reason) when coins-best is not yet derivable — it
 * never undoes the committed import. */
bool shielded_history_import_register_cured_tip_trust_anchor(
    struct sqlite3 *progress_db, struct node_db *ndb);

#endif /* ZCL_SERVICES_SHIELDED_HISTORY_IMPORT_SERVICE_H */
