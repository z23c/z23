/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair — reducer-stage repair helpers used by Conditions.
 *
 * These helpers operate on progress.kv, the reducer's durable cursor/log
 * store. They intentionally live with Jobs rather than Conditions so each
 * Condition stays a small detect/remedy/witness file. */

#ifndef ZCL_JOBS_STAGE_REPAIR_H
#define ZCL_JOBS_STAGE_REPAIR_H

#include "core/uint256.h"
#include "primitives/block.h"

#include <stdbool.h>

struct sqlite3;
struct main_state;

enum stage_repair_header_solution_poison {
    STAGE_REPAIR_POISON_NONE = 0,
    STAGE_REPAIR_POISON_VALIDATE_SOLUTIONLESS,
    STAGE_REPAIR_POISON_VALIDATE_HASH_MISMATCH,
    STAGE_REPAIR_POISON_DOWNSTREAM_STALE,
};

enum stage_repair_tipfin_refused_reason {
    STAGE_REPAIR_TIPFIN_REFUSED_NONE = 0,
    STAGE_REPAIR_TIPFIN_REFUSED_G1_COIN_UNKNOWN = 1,
    STAGE_REPAIR_TIPFIN_REFUSED_G2_EVIDENCE_ROW = 2,
    STAGE_REPAIR_TIPFIN_REFUSED_G2_ROW_PRESENT = 3,
    STAGE_REPAIR_TIPFIN_REFUSED_G3_MISSING_EVIDENCE = 4,
    STAGE_REPAIR_TIPFIN_REFUSED_G4_AT_SERVED_FLOOR = 5,
    STAGE_REPAIR_TIPFIN_REFUSED_G5_BINDER_MISSING = 6,
    STAGE_REPAIR_TIPFIN_REFUSED_G6_IN_TX_RECHECK = 7,
    STAGE_REPAIR_TIPFIN_REFUSED_G7_MARKER_SEEN = 8,
    STAGE_REPAIR_TIPFIN_REFUSED_HSTAR_RANGE = 9,
};

enum stage_repair_tipfin_refused_log {
    STAGE_REPAIR_TIPFIN_LOG_UNKNOWN = 0,
    STAGE_REPAIR_TIPFIN_LOG_VALIDATE_HEADERS = 1,
    STAGE_REPAIR_TIPFIN_LOG_SCRIPT_VALIDATE = 2,
    STAGE_REPAIR_TIPFIN_LOG_VALIDATE_SCRIPT_SPLIT = 3,
    STAGE_REPAIR_TIPFIN_LOG_BODY_PERSIST = 4,
    STAGE_REPAIR_TIPFIN_LOG_PROOF_VALIDATE = 5,
    STAGE_REPAIR_TIPFIN_LOG_UTXO_APPLY = 6,
    STAGE_REPAIR_TIPFIN_LOG_TIP_FINALIZE = 7,
    STAGE_REPAIR_TIPFIN_LOG_HEADER_ADMIT = 8,
};

struct stage_repair_header_solution_result {
    bool repaired;
    int target_height;
    int deleted_rows;
    int rewound_cursors;
    enum stage_repair_header_solution_poison mode;
};

struct stage_repair_body_fetch_gap {
    bool ready;
    bool body_observed;
    bool has_target_hash;
    struct uint256 target_hash;
    int target_height;
    int validate_cursor;
    int body_fetch_cursor;
};

struct node_db;

/* Outcome of one runtime poisoned-blocks-row quarantine attempt
 * (stage_repair_quarantine_blocks_row). Exactly one of quarantined /
 * refused_clean / row_absent / no_params is the operative result on a given
 * call; `verdict` carries the enum block_row_verify_result the frozen verify
 * produced. */
struct stage_repair_row_quarantine_result {
    bool attempted;      /* the evidence gate ran (a candidate row was read) */
    bool quarantined;    /* row FAILED the frozen verify AND was purged */
    bool refused_clean;  /* row PASSED the frozen verify — deliberately NOT deleted */
    bool row_absent;     /* no addressable `blocks` row at (hash | height) */
    bool no_params;      /* chain params unavailable — cannot prove evidence, refused */
    bool deleted_by_height; /* purge used db_block_delete_by_height (hash unusable) */
    int  height;
    int  verdict;        /* enum block_row_verify_result */
};

/* Runtime cure (Lane B3): purge a poisoned `blocks`-table row at `height` whose
 * durable header/solution the frozen verify REJECTS, so header sync + body_fetch
 * re-request a clean body instead of the repair loop re-hitting the same poison
 * forever. Evidence-gated and conservative: the row is read RAW and run through
 * block_row_verify() against the canonical `hash`; the DELETE fires ONLY on a
 * concrete failure verdict (hash-bind / high-hash / bad-Equihash). A row that
 * verifies OK is REFUSED (never "row looks odd"). On a fired quarantine it also
 * clears BLOCK_HAVE_DATA on the in-memory canonical block_index entry (via `ms`,
 * best-effort) and re-emits the header event so the cleared re-fetch state is
 * durable, bumps the process counter (stage_repair_runtime_row_quarantined), and
 * raises a TRANSIENT typed blocker naming height+hash+verdict. Never touches
 * tip_finalize_log, never lowers the served floor. `out` may be NULL. Returns
 * true iff a row was purged. */
bool stage_repair_quarantine_blocks_row(
    struct node_db *ndb, struct main_state *ms, int64_t height,
    const struct uint256 *hash,
    struct stage_repair_row_quarantine_result *out);

/* Process-monotonic tally of poisoned `blocks` rows purged by the RUNTIME
 * quarantine above (distinct from the boot-time blocks-hydrate tally). Surfaced
 * by diag_block_index_dump_state_json. Reentrant/lock-free. */
int64_t stage_repair_runtime_row_quarantined(void);

enum stage_repair_header_solution_poison
stage_repair_header_solution_poison_mode(struct sqlite3 *db, int height);

bool stage_repair_header_solution_repairable_validate_frontier(
    struct sqlite3 *db,
    int *out_height);

bool stage_repair_header_solution_save(struct sqlite3 *db,
                                       int height,
                                       const struct uint256 *hash,
                                       const struct block_header *header);

bool stage_repair_header_solution_load(struct sqlite3 *db,
                                       int height,
                                       const struct uint256 *expected_hash,
                                       struct block_header *out);

/* Returns true iff a header-solution row is present at `height` AND — when
 * `expected_hash != NULL` — its stored hash equals expected_hash, i.e. the
 * CORRECT solution for the canonical block at that height is present. Pass NULL
 * for a presence-only check (any row that round-trips). Hash-aware callers pass
 * active_chain_at(height)->phashBlock so a STALE wrong-block row (e.g. an
 * earlier off-by-N save) does NOT count as available — otherwise the backfill /
 * self-heal paths would skip a height whose stored solution validate_headers
 * (whose load IS hash-checked) keeps rejecting, wedging the tip. */
bool stage_repair_header_solution_available(struct sqlite3 *db, int height,
                                            const struct uint256 *expected_hash);

bool stage_repair_header_solution_poison_rewind(
    struct sqlite3 *db,
    int height,
    int active_tip_height,
    struct stage_repair_header_solution_result *out);

bool stage_repair_body_fetch_missing_have_data_candidate(
    struct sqlite3 *db,
    int height,
    struct stage_repair_body_fetch_gap *out);

bool stage_repair_body_fetch_missing_have_data_frontier_candidate(
    struct sqlite3 *db,
    struct stage_repair_body_fetch_gap *out);

bool stage_repair_body_fetch_observed(struct sqlite3 *db, int height);
bool stage_repair_body_fetch_observed_hash(
    struct sqlite3 *db, int height, const struct uint256 *expected_hash);

struct stage_reconcile_result {
    bool clamped;   /* the tip_finalize cursor was strictly above floor and moved */
    int  floor;     /* coins_best: highest durably applied block height */
};

struct stage_reducer_frontier_reconcile_result {
    bool repaired;
    bool clamped_tip_finalize;
    bool refused_coin_tear;
    bool refused_coin_unknown;
    bool coins_applied_found;
    int hstar;
    int served_floor;
    int coins_applied_height;
    bool clamped_validate_headers;
    int validate_headers_cursor_before;
    int validate_headers_cursor_after;
    bool clamped_body_fetch;
    int body_fetch_cursor_before;
    int body_fetch_cursor_after;
    bool clamped_body_persist;
    int body_persist_cursor_before;
    int body_persist_cursor_after;
    int tip_finalize_cursor_before;
    int tip_finalize_cursor_after;
    int sweep_top;
    int lowest_have_data_cleared;
    int lowest_validate_headers_refill_hole;
    int lowest_validate_headers_hash_split;
    /* Lowest validate/script hash_split classified as SCRIPT-side (script
     * disagrees with the canonical active header). Owned by the coins-rewinding
     * dual replay, NOT the validate-cursor clamp: the clamp re-derives the same
     * canonical header and leaves the stale script row, so counting it as
     * `repaired` would self-clear without H* advancing. The refill sets this
     * (and resets lowest_validate_headers_hash_split to -1 for the same height)
     * so the clamp stays validate-side-only and the repaired rollup can exclude
     * a non-advancing clamp for an unresolved script-side split. */
    int lowest_script_validate_hash_split;
    int lowest_body_fetch_refill_hole;
    int lowest_body_persist_refill_hole;
    int scripts_set;
    int have_data_set;
    int have_data_cleared;
    int failed_mask_cleared;
    int header_events_emitted;
    bool value_overflow_repair_attempted;
    bool value_overflow_repaired;
    bool value_overflow_repair_owner_refused;
    bool value_overflow_repair_marker_seen;
    bool value_overflow_repair_genuinely_invalid;
    int value_overflow_repair_height;
    int value_overflow_cursor_before;
    int value_overflow_cursor_after;
    bool stale_script_repair_attempted;
    bool stale_script_repaired;
    bool stale_script_repair_marker_seen;
    bool stale_script_repair_genuinely_invalid;
    int stale_script_repair_height;
    int stale_script_cursor_before;
    int stale_script_cursor_after;
    int stale_script_backfill_first;
    int stale_script_backfill_last;
    int stale_script_utxo_cursor_before;
    int stale_script_tip_cursor_before;
    bool coin_backfill_attempted;
    int coin_backfill_status; /* enum coin_backfill_status */
    int coin_backfill_hole_height;
    int coin_backfill_unresolved;
    int coin_backfill_inserted;
    int coin_backfill_scan_next;
    bool coin_backfill_owner_refused;
    bool coin_backfill_genuinely_invalid;
    int lowest_script_validate_refill_hole;
    int lowest_proof_validate_refill_hole;
    bool clamped_script_validate;
    bool clamped_proof_validate;
    int script_validate_cursor_before;
    int script_validate_cursor_after;
    int proof_validate_cursor_before;
    int proof_validate_cursor_after;
    bool pre_refusal_unapplied_clamp;
    int tipfin_backfill_height;
    int tipfin_backfill_count;
    bool tipfin_backfill_marker_seen;
    /* enum stage_repair_tipfin_refused_reason code; 0 =
     * STAGE_REPAIR_TIPFIN_REFUSED_NONE. The refusal WARN names the guard in
     * text; *_height/log expose the precise evidence boundary to Conditions
     * without parsing node.log. */
    int tipfin_backfill_refused_reason;
    int tipfin_backfill_refused_height;
    int tipfin_backfill_refused_log;
    /* Non-canonical row purge (stage_repair_reducer_frontier_purge.c):
     * stage-log rows whose stored hash doesn't match the canonical block
     * at their height — relabel/reorg residue. found counts rows judged
     * stale (dry-run too); purged counts actual deletions (apply only). */
    int noncanonical_found;
    int noncanonical_purged;
    int lowest_noncanonical;
    /* Stale reorg-residue tip_finalize verdict REPLACEMENT (FIX-A,
     * stage_repair_reducer_frontier_purge.c): an ok=0 skip-status
     * tip_finalize_log row (reorg_detected / utxo_count_diverged residue)
     * left at a height already covered by coins (h <= coins_applied-1) and
     * re-evidenced upstream (header_admit_log present at h) caps H* below the
     * coins frontier, manufacturing a FALSE coin-tear refusal even though a
     * contiguous column above it is fully refillable. The replacement writes
     * a fresh ok=1 'finalize_backfill' verdict (row REPLACED in place — never
     * deleted, served_floor preserved) so the row stops capping H*; the
     * existing header_admit-keyed refill + tip_finalize clamp then re-derive
     * the column. found counts rows judged stale (dry-run too); replaced
     * counts in-place rewrites (apply only). */
    int reorg_residue_tipfin_found;
    int reorg_residue_tipfin_replaced;
    int lowest_reorg_residue_tipfin;
    /* Label-splice re-bind (stage_repair_reducer_frontier_rebind.c): a
     * pre-stamping NULL-block_hash suffix in proof_validate_log /
     * script_validate_log at/above the utxo_apply frontier makes utxo_apply's
     * label_splice guard refuse ("verdict is hash-bound to a different block").
     * The re-bind rewinds ONLY the proof/script VALIDATION cursors to the lowest
     * NULL height (floored at MIN(utxo_apply, tip_finalize)) and deletes the NULL
     * suffix so the forward fold re-derives + re-stamps block_hash. Never touches
     * coins, nullifiers, or tip_finalize. lowest = the lowest NULL height a
     * re-bind would/did target (-1 = none pending, set in dry-run AND apply);
     * rebound = count of validation cursors actually rewound this apply pass
     * (0/1/2, apply only); the *_rewound_to / deleted_rows fields are apply-only
     * detail. */
    int label_splice_rebind_lowest;
    int label_splice_rebound;
    int label_splice_proof_rewound_to;
    int label_splice_script_rewound_to;
    int64_t label_splice_deleted_rows;
};

/* Result classifiers used by the Condition and memo cache. Keep this seam
 * named: the coin-frontier group is the borrowed-seed recovery scaffold that
 * should shrink after the self-verified UTXO anchor rebuild cure
 * (-refold-from-anchor), while the row-residue group is retained liveness
 * repair. */
static inline bool stage_reducer_frontier_result_has_coin_repair_evidence(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    return rr &&
           (rr->value_overflow_repair_attempted ||
            rr->value_overflow_repair_owner_refused ||
            rr->stale_script_repair_attempted ||
            rr->coin_backfill_attempted ||
            rr->coin_backfill_owner_refused ||
            rr->tipfin_backfill_count > 0 ||
            rr->tipfin_backfill_refused_reason != 0);
}

static inline bool stage_reducer_frontier_result_has_row_residue_evidence(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    return rr &&
           (rr->noncanonical_found > 0 ||
            rr->reorg_residue_tipfin_found > 0);
}

/* Rowless stage-log refill holes below a stage cursor (e.g. the residue of a
 * noncanonical purge that deleted stale-hash rows without clamping the
 * cursor): a *_log row is absent at a height the cursor already passed, so
 * the stage never re-derives it and H* stays pinned one below the hole.
 * Sentinel is -1 = no hole (the reconcile initializes all five to -1 before
 * the scan; a zeroed struct reads as a hole at height 0 — initialize like the
 * reconcile does). Suppressing a result carrying one of these MUST be loud:
 * a silently-discarded script_validate/proof_validate refill pins H*
 * indefinitely with no operator-visible signal. */
static inline bool stage_reducer_frontier_result_has_refill_hole_evidence(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    return rr &&
           (rr->lowest_validate_headers_refill_hole >= 0 ||
            rr->lowest_body_fetch_refill_hole >= 0 ||
            rr->lowest_body_persist_refill_hole >= 0 ||
            rr->lowest_script_validate_refill_hole >= 0 ||
            rr->lowest_proof_validate_refill_hole >= 0);
}

/* A label-splice re-bind is pending (dry-run) or fired (apply): a
 * NULL-block_hash proof/script suffix at/above the utxo_apply frontier. This is
 * durable below-frontier internal damage, peer-independent, and its own
 * actionable class (never a coin-tear or refill hole). Detect keys on this so
 * the Condition activates for the pure label_splice wedge even when no coin arm
 * fires. */
static inline bool stage_reducer_frontier_result_has_label_splice_rebind_evidence(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    return rr &&
           (rr->label_splice_rebind_lowest >= 0 ||
            rr->label_splice_rebound > 0);
}

static inline bool stage_reducer_frontier_result_has_gate_loudness_evidence(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    return stage_reducer_frontier_result_has_coin_repair_evidence(rr) ||
           stage_reducer_frontier_result_has_row_residue_evidence(rr) ||
           stage_reducer_frontier_result_has_refill_hole_evidence(rr) ||
           stage_reducer_frontier_result_has_label_splice_rebind_evidence(rr);
}

static inline bool stage_reducer_frontier_result_is_memo_clean(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    return rr &&
           !rr->repaired &&
           !rr->refused_coin_tear &&
           !rr->refused_coin_unknown &&
           !stage_reducer_frontier_result_has_gate_loudness_evidence(rr);
}

/* Reconcile a reducer cursor/coins desync that wedges the chain.
 *
 * After an unclean restart (kill-9 + WAL) the durable tip_finalize cursor can
 * sit AHEAD of the durably-applied coins tip (`coins_best`). tip_finalize then
 * idles ("cursor says done") and never re-finalizes, so the connect gate
 * rejects every block at coins_best+1 with "block-not-finalized-by-reducer".
 *
 * This reconciles ONLY the tip_finalize cursor to `coins_best`, the highest
 * durably applied block height. Durable tip_finalize_log rows above that
 * frontier are preserved as forensic/public-floor evidence, but they are not
 * executable authority: raising the cursor above coins_best recreates the
 * uv_cursor_gap wedge where tip_finalize waits ahead of utxo_apply forever.
 * Upstream logs/cursors are left untouched, so any re-finalize pass still has
 * its evidence.
 *
 * SAFETY (proven in test_stage_reducer_unwedge):
 *   - It NEVER deletes any *_log row, and it never writes the tip_finalize
 *     cursor above the durably applied coins frontier. The public served-floor
 *     evidence is preserved by keeping tip_finalize_log rows intact.
 *   - It touches ONLY the tip_finalize cursor — no upstream cursor or log — so
 *     the re-finalize cannot self-stall.
 *   - No-op (clamped=false) when the tip_finalize cursor already equals the
 *     target; refuses (returns true, clamped=false) when `coins_best < 0`
 *     (no durable anchor to floor on).
 *
 * Must run at boot AFTER coins_best is durable and BEFORE the stages init (so
 * they load the clamped cursor). Single transaction. */
bool stage_reconcile_clamp_tip_finalize_to_floor(
    struct sqlite3 *db,
    int coins_best,
    struct stage_reconcile_result *out);

const char *stage_repair_tipfin_refused_reason_label(int reason);
const char *stage_repair_tipfin_refused_log_label(int log);
bool stage_repair_tipfin_refusal_is_pending_forward(
    const struct stage_reducer_frontier_reconcile_result *rr);

/* L1 reducer-frontier reconcile: repair block_index mirror flags from
 * hash-bound durable reducer logs, rewind validate_headers/body_fetch/
 * body_persist to the lowest missing admitted/validated/body row or cleared
 * HAVE_DATA hole so forward-only stages can refill the gap, then clamp
 * tip_finalize to the coin-capped H*+1 floor so tip_finalize can replay
 * forward. This is a flag/cursor repair only: it never deletes log rows and
 * never mutates coins. If coins_applied_height is absent or present above H*,
 * the helper refuses (unknown/L2 coin-tear domain).
 *
 * LOCK ORDER — cs_main OUTER, progress store INNER, and the inner acquire is
 * a TRYLOCK. This function holds both, and it is the only one that may, at
 * the cost of never being allowed to WAIT for the second one.
 *
 * There is no single global order available to conform to, because the tree
 * changes order partway through boot:
 *   - Before the height authority is registered, active_chain_height() and
 *     active_chain_tip() (core/modules/validation/src/chainstate.c) read the progress
 *     store internally, so the ~two dozen cs_main holders that call them —
 *     sync_monitor.c, sticky_escalator_trigger.c, body_backfill_service.c,
 *     gap_fill_service.c, accept_to_mempool.c, several self-heal Conditions —
 *     all nest cs_main -> progress.
 *   - After tip_finalize_stage_init registers it, is_authoritative() returns
 *     true unconditionally (engine/jobs/src/tip_finalize_stage.c) and that edge
 *     disappears for the rest of the process. What remains is the reducer
 *     drive running the OPPOSITE way on every advancing block:
 *     STAGE_DRAIN_IMPL (engine/jobs/include/jobs/job.h) holds
 *     progress_store_tx_lock across the entire drain and body_fetch's step
 *     takes cs_main inside it (engine/jobs/src/body_fetch_stage.c).
 *
 * A blocking acquire here closes an ABBA cycle against whichever phase it
 * does not match — progress-first deadlocked the boot window (a node wedged
 * partway through startup, P2P port open, RPC port never opening, because
 * script_validate_stage_init blocked forever on the progress store);
 * cs_main-first deadlocks the steady state against the drive. Both are the
 * same bug wearing different clothes, and neither is fixed by reordering.
 *
 * The resolution is to stop waiting. This reconcile is a self-heal observer
 * on the condition-engine thread (and via sticky_escalator the supervisor
 * sweep thread), so progress_store_tx_trylock() — the progress store's
 * documented "non-blocking counterpart for observational surfaces", used the
 * same way by engine/reducer/conditions/src/reducer_drive_watchdog.c — lets it decline
 * and retry on the next tick. A path that never waits-for cannot be half of
 * a deadlock, whichever way the rest of the tree happens to be nesting.
 * Regression cover: the "lock-order" cases in
 * tests/harness/src/test_reducer_frontier_reconcile_light.c. */
bool stage_reducer_frontier_reconcile_light_needed(
    struct sqlite3 *db,
    struct main_state *ms,
    struct stage_reducer_frontier_reconcile_result *out);

bool stage_reducer_frontier_reconcile_light(
    struct sqlite3 *db,
    struct main_state *ms,
    struct stage_reducer_frontier_reconcile_result *out);

#ifdef ZCL_TESTING
/* Test-only: drop the dry-run detect memo so the next reconcile re-sweeps. Call
 * between fixtures that close+reopen progress.kv (see the definition comment). */
void stage_reducer_frontier_reset_detect_memo_for_testing(void);

/* Test-only: enter reconcile_block_index_flags DIRECTLY — the one function
 * that holds cs_main and the progress store at the same time.
 *
 * The public entry point cannot stage the lock-order race: it calls
 * read_frontier_snapshot() first, which takes the progress store on its own
 * (holding no cs_main, so it is safe), and a test that contends the progress
 * store simply parks the caller there and never reaches the section that
 * matters. A regression test written against the public path therefore passes
 * whether the acquire below is a trylock or a blocking lock — it proves
 * nothing. This seam skips the prologue so the test can hold the progress
 * store, call in, and observe whether cs_main is held while waiting. */
bool stage_reducer_frontier_reconcile_flags_for_testing(
    struct sqlite3 *db,
    struct main_state *ms,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out);

/* Test-only witness for the proof_validate internal_error symmetry
 * (self-verified-tip-plan Act 1). The caller seeds the script/proof/utxo log +
 * cursor shape; this runs the lowest proof-only internal_error detect + the
 * one-shot rewind purely over the progress store (no main_state, no disk block
 * read). On a fired rewind the proof_validate_log row(s) at the hole are
 * DELETED so proof_validate re-derives the verdict (never re-reads the frozen
 * ok=0). Returns false only on a store error; *repaired / *out_height report
 * whether and where a rewind fired. Marker is keyed on a zero block hash. */
bool stage_repair_proof_internal_error_rewind_for_testing(
    struct sqlite3 *db, bool *repaired, int *out_height);

/* Test-only witnesses for the hash_split (validate-script-hash-mismatch) class.
 * detect returns the lowest height where validate_headers.hash !=
 * script_validate.block_hash (or -1). rewind applies the coins-not-advanced
 * subset of the one-shot replay (delete the stale script+proof verdicts +
 * rewind script/proof/tip so the forward stages re-derive). Pure progress-store
 * ops; production uses maybe_repair_validate_script_hash_split with the full
 * block-read + coins safety. */
bool stage_repair_validate_script_hash_split_detect_for_testing(
    struct sqlite3 *db, int *out_height);
bool stage_repair_validate_script_hash_split_rewind_for_testing(
    struct sqlite3 *db, bool *repaired, int *out_height);

/* Test-only: drop the tip_finalize rewind-churn memo (see
 * tip_finalize_rewind_churn_gate in stage_repair_reducer_frontier.c). Call
 * between fixtures so a prior test's streak/blocker never leaks in. */
void stage_reducer_frontier_reset_rewind_churn_memo_for_testing(void);

/* Test-only witness for the tip_finalize rewind-churn refusal: drives the
 * cursor clamp/rewind directly from a caller-populated result (`hstar`,
 * `tip_finalize_cursor_before`, optionally `coins_applied_found` /
 * `coins_applied_height`) without a main_state/active-chain fixture. */
bool stage_reducer_frontier_reconcile_tip_finalize_cursor_for_testing(
    struct sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out);
#endif

#endif /* ZCL_JOBS_STAGE_REPAIR_H */
