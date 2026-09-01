/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_delta - inverse-delta persistence and reorg-unwind helpers.
 * Internal to the utxo_apply job: captures per-block UTXO preimages so a
 * stage-side disconnect can reconstruct the abandoned branch without legacy
 * undo files.
 *
 * Not a public API — only utxo_apply_stage.c includes this. The two
 * delta types are shared by compute_block_delta (which fills them) and
 * the persistence/unwind code (which serializes and inverts them). */

#ifndef ZCL_JOBS_UTXO_APPLY_DELTA_H
#define ZCL_JOBS_UTXO_APPLY_DELTA_H

#include "core/uint256.h"
#include "jobs/utxo_apply_stage.h"  /* utxo_apply_lookup_fn */

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct block;
struct main_state;
struct stage;

/* One created/restored coin in a block delta. */
struct delta_entry {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
    /* Added entries carry the coin fields the apply path writes.
     * `script` aliases into the live `struct block` and is valid only
     * until block_free — the apply must happen before the block is freed.
     *
     * Spent entries also carry the full pre-image (height + is_coinbase
     * + script) so a stage-side disconnect can emit a correct restore-ADD
     * (the inverse of the SPEND). For a spent entry the script bytes live in
     * the owned `script_owned` buffer (the live block's tx_out is gone by
     * disconnect time), and `script` aliases into it; `height` is the coin's
     * ORIGINAL creation height. For an added entry `script` aliases the live
     * block and `script_owned` is NULL. */
    const uint8_t *script;
    uint32_t script_len;
    bool is_coinbase;
    uint32_t height;        /* spent: coin's original creation height */
    uint8_t *script_owned;  /* spent: owned copy of the restore script */
};

/* The full transparent UTXO delta of one block. */
struct delta_summary {
    bool ok;
    const char *status;
    const char *failure_kind;
    uint8_t failure_detail[36];
    size_t spent_count;
    size_t added_count;
    int64_t total_value_delta;
    /* On a successful delta these own the spent/added arrays and are
     * handed back to the caller (which emits then frees). On any
     * failure path compute_block_delta frees them and leaves NULL. */
    struct delta_entry *spent;
    struct delta_entry *added;
    /* REPLAY GATE (D2 count-and-continue) — set ONLY when the env gate
     * ZCL_REPLAY_COUNT_ONLY is active AND this block tripped the coinbase
     * -maturity predicate (a fire was logged+counted). It is NOT a normal
     * reject: ok stays true, but the stage MUST author NO coins for this
     * block and continue WITHOUT halting the frontier (strictly
     * read/log/continue). When the env is unset this is always false and
     * the stage takes its normal author/reject path. See jobs/replay_count_only.h. */
    bool count_only_d2_skip;
};

/* Free a delta-entry array, releasing any owned restore-scripts in the
 * first `n` entries (only spent entries below the running count carry
 * one). `n` may be 0 to free only the array block. */
void free_delta_arr(struct delta_entry *arr, size_t n);
/* Free both arrays of a summary (spent/added) up to their counts. */
void free_delta(struct delta_summary *s);

/* DEFAULT-OFF coinbase-maturity parity reject on the live reducer fold.
 * When true, utxo_apply_compute_block_delta rejects a spend of a coinbase
 * output younger than COINBASE_MATURITY (100) with failure_kind
 * "bad-txns-premature-spend-of-coinbase", matching zclassicd CheckTxInputs
 * (zclassic-cpp/src/main.cpp:2056-2060). Default false ⇒ the fold makes the
 * same accept/reject decision it makes now (no such reject). ⚠ Enabling this is a tightening
 * predicate: do NOT flip the default or pass -enforce-coinbase-maturity on
 * the live node until a FULL-HISTORY REPLAY confirms ZERO false-rejects
 * (h=478544 lesson). Set by the node from the -enforce-coinbase-maturity
 * argv flag (engine/entry/main.c). _Atomic so background threads read it lock-free. */
extern _Atomic _Bool g_enforce_coinbase_maturity;

/* Compute the transparent UTXO delta of one block, capturing the full
 * pre-image of each spent coin (value/height/is_coinbase/script) so a
 * later disconnect can emit a correct restore-ADD. Unresolved prevouts
 * are looked up via `lookup` (NULL → all external coins are "absent").
 * On success `out->spent` / `out->added` own the arrays (caller emits
 * then free_delta()s); on any failure `out` is freed and ok==false with
 * a status/failure_kind set. `block_height` is this block's height (used
 * as the restore height for an intra-block create-then-spend coin). */
void utxo_apply_compute_block_delta(const struct block *blk,
                                    uint32_t block_height,
                                    utxo_apply_lookup_fn lookup,
                                    void *lookup_user,
                                    struct delta_summary *out);

/* Ensure the durable per-block inverse-delta table exists. */
bool utxo_apply_ensure_delta_schema(sqlite3 *db);

/* Shared transactional rewind primitive.  Delete every reducer-owned row
 * whose creation height is in [first_height,last_height], including durable
 * nullifiers and Sprout/Sapling anchors.  The caller owns the transaction;
 * rollback therefore restores every projection together.  Reorg, repair,
 * replay, and focused parity tests all route through this one seam. */
bool utxo_apply_delete_rows_above(sqlite3 *db, int first_height,
                                  int last_height);

/* Remove abandoned reducer-kernel rows at/above the next unapplied height.
 * This startup repair mutates only when the durable stage cursor and coin
 * frontier agree exactly; it never changes either authority.  If coin rows
 * also survived above that frontier, canonical bodies must prove the exact
 * suffix outputs and every restorable transparent spend before mutation. */
bool utxo_apply_reconcile_unapplied_suffix(
    sqlite3 *db, struct main_state *ms, const char *datadir,
    utxo_apply_reader_fn reader, void *reader_user);

/* Persist the per-block inverse-delta for `height`, stamped with the
 * OLD branch hash. MUST run inside the stage txn so it lands atomically
 * with the log row + cursor. Called only on a successful apply. */
bool utxo_apply_delta_persist(sqlite3 *db, int height,
                              const struct uint256 *branch_hash,
                              const struct delta_summary *s);

/* The stage-side disconnect path. Detects an active-chain reorg below
 * the persisted cursor, walks down to the fork point, emits inverse
 * UTXO events for the abandoned blocks (when author==STAGE), deletes the
 * now-invalid log+delta rows, and rewinds the cursor to the fork
 * boundary — bounded by ZCL_FINALITY_DEPTH. Self-contained transaction
 * for the row deletes + cursor write. On any unwind, *unwound_counter is
 * incremented and *last_blocked_unix is stamped. Returns false on error
 * (the caller surfaces JOB_FATAL); cursor untouched on error. */
bool utxo_apply_reorg_unwind_if_needed(sqlite3 *db,
                                       struct stage *stage,
                                       struct main_state *ms,
                                       _Atomic uint64_t *unwound_counter,
                                       _Atomic int64_t *last_blocked_unix);

struct utxo_apply_value_overflow_repair_result {
    bool attempted;
    bool repaired;
    bool owner_refused;
    bool marker_seen;
    bool genuinely_invalid;
    bool dry_run_ok;
    /* The persisted utxo_apply cursor no longer matches the caller's
     * snapshot (it advanced in the caller's unlock gap) — refused without
     * mutation; retry next tick re-evaluates fresh state. */
    bool cursor_stale_refused;
    /* The [height .. cursor-1] log/delta pairing is torn (missing log row,
     * or ok==1 without a delta row, or a delta row without ok==1): the
     * inverse walk would rewind PARTIALLY — refused without mutation. */
    bool walk_torn_refused;
    int height;
    uint64_t cursor_before;
    uint64_t cursor_after;
};

/* One-shot repair for a stale value_overflow utxo_apply_log hole below the
 * current utxo_apply cursor. The caller supplies the exact hole height, the
 * currently observed cursor, and the canonical block body/hash for that height.
 * This function reasserts every consensus guard itself: STAGE author, the
 * persisted cursor still equals the caller's snapshot (re-read under the
 * progress lock — the caller released it for the disk block read), row still
 * ok=0/status=value_overflow below cursor, (height,block_hash) marker has not
 * been attempted, the [height..cursor-1] log/delta pairing is consistent (a
 * missing delta row would make the inverse walk a PARTIAL rewind), and a
 * current-binary dry-run succeeds. On success it uses the same inverse-delta
 * machinery as reorg unwind in one BEGIN IMMEDIATE. The stage cursor is "next
 * height to apply", so rewinding cursor/frontier to `height` leaves coins
 * applied through height-1 and makes forward apply re-run the stale hole.
 * Records the marker in the same transaction. */
bool utxo_apply_repair_value_overflow_hole(
    sqlite3 *db,
    int height,
    uint64_t cursor,
    const struct uint256 *block_hash,
    const struct block *blk,
    struct utxo_apply_value_overflow_repair_result *out);

/* Name a deep-reorg refusal as the typed blocker
 * `chain.reorg_refused_below_finality` (BLOCKER_PERMANENT). Called by BOTH
 * refusal paths in utxo_apply_delta_reorg.c — the fork-walk exhaustion and
 * the reorg_is_allowed gate — so a refusal can no longer be a stderr line
 * that nothing typed. `tip_h` is the stage's tip (cursor-1) and `fork_h` the
 * fork point (may be negative when the walk found none).
 *
 * Exported rather than static so the FIRING is directly testable: with
 * ZCL_FINALITY_DEPTH = 10 this refusal never resolves itself, which makes it
 * exactly the raise that must not be taken on trust. Pure apart from the
 * blocker registry write — no DB, no clock beyond the registry's own.
 * Remedy/decision rows: blocker_remedy_bindings.def /
 * blocker_operator_decisions.def. */
void utxo_apply_reorg_name_refusal_blocker(int tip_h, int fork_h);

#endif /* ZCL_JOBS_UTXO_APPLY_DELTA_H */
