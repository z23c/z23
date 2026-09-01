/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_stage — reducer Job stage.
 *
 * Consumes `proof_validate_log`; for each height where proof validation
 * passed, computes the transparent UTXO delta, records the result, and emits
 * stage-authored UTXO projection deltas when the stage owns projection
 * authority. */

#ifndef ZCL_SERVICES_UTXO_APPLY_STAGE_H
#define ZCL_SERVICES_UTXO_APPLY_STAGE_H

#include "core/uint256.h"
#include "jobs/stage_helpers.h"
#include "util/stage.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct block;
struct block_index;
struct json_value;
struct main_state;
struct sqlite3;
struct tx_out;

#define UTXO_APPLY_BATCH_PER_TICK 100

/* The sole state-frontier writer lives in utxo_apply_stage.c. Recovery,
 * reorg, boot, and install transactions call this request name; the alias
 * deliberately routes every request through the manifest-owned function
 * without cloning the write primitive into those callers. */
bool coins_kv_set_applied_height_in_tx(struct sqlite3 *db, int32_t height);
#define utxo_apply_frontier_set_in_tx coins_kv_set_applied_height_in_tx

/* The full pre-image of a coin, as needed to emit a correct restore-ADD
 * on a stage-side reorg unwind (the inverse of the SPEND emitted when an
 * input is first consumed). value alone is insufficient: the projection
 * commitment is taken over (txid|vout|value|script|height|is_coinbase),
 * so a restored coin MUST carry its original height/is_coinbase/script
 * or the post-reorg commitment diverges from a direct fold. Mirrors exactly
 * what the former disconnect block path pulls from undo->txout/undo->height
 * (connect_block.c:733-757).
 *
 * `script` points into caller-owned storage and is copied immediately by
 * compute_block_delta; it need not outlive the lookup call. A UTXO
 * scriptPubKey is consensus-bounded to MAX_SCRIPT_SIZE, which is exactly
 * UTXO_APPLY_SCRIPT_MAX — so the buffer always holds the full script and
 * the lookup MUST return it whole (the projection stores it whole). If
 * `script_len` ever exceeds UTXO_APPLY_SCRIPT_MAX (a contract violation,
 * unreachable with valid chain data) compute_block_delta FAILS the delta
 * rather than over-read the buffer or persist a truncated coin. */
#define UTXO_APPLY_SCRIPT_MAX 10000

struct utxo_apply_lookup {
    bool found;
    int64_t value;
    /* Full pre-image (see comment above). Only meaningful when found. */
    uint32_t height;
    bool is_coinbase;
    uint32_t script_len;
    uint8_t script[UTXO_APPLY_SCRIPT_MAX];
};

/* Alias onto the shared stage reader type (jobs/stage_helpers.h); the public
 * setter name utxo_apply_stage_set_reader is unchanged. */
typedef stage_block_reader_fn utxo_apply_reader_fn;

typedef bool (*utxo_apply_lookup_fn)(const struct uint256 *txid,
                                     uint32_t vout,
                                     struct utxo_apply_lookup *out,
                                     void *user);

bool utxo_apply_stage_init(struct main_state *ms);
void utxo_apply_stage_shutdown(void);

job_result_t utxo_apply_stage_step_once(void);
int utxo_apply_stage_drain(int max_steps);

/* A commitment-tree rebuild replaces the Sapling frontier as one verified
 * unit. Coin/anchor application must remain parked for that interval; folding
 * even one block from the pre-rebuild frontier can create a durable false
 * sapling_frontier_mismatch above an otherwise correct replay. */
bool utxo_apply_sapling_rebuild_paused(void);

/* Test observability for the lane-A1 decoupled created_outputs prune: `runs`
 * counts how many times the post-commit prune tx committed; `last_floor` is the
 * retention floor of the most recent successful prune (-1 if none). Both may be
 * NULL. */
void utxo_apply_post_prune_stats(uint64_t *runs, int64_t *last_floor);

/* Test-only: lower the created_outputs retention window (default is thousands
 * of blocks) so the decoupled post-commit prune fires over a short synthetic
 * chain. -1 restores the compile-time default. */
void utxo_apply_created_outputs_retain_set_for_test(int retain_blocks);

uint64_t utxo_apply_stage_cursor(void);
/* Step-timing EWMA (us); see util/stage.h. 0 if never stepped. */
int64_t  utxo_apply_stage_step_us_ewma(void);

/* True iff utxo_apply durably recorded a successful (ok=1) application at
 * `height`. utxo_apply is downstream of script_validate + proof_validate, so
 * an ok=1 row here implies both of those passed at `height`. The reducer
 * front door uses this to accept a freshly-ingested tip block that cleared
 * all stateful validation but cannot be tip_finalized yet — tip_finalize
 * needs the successor block (H+1) as lookahead, so the live tip is never
 * finalized within the same ingest call. Returns false if no row or ok!=1. */
bool utxo_apply_stage_succeeded_at(int height);

/* Height + kind of the stage's most recent select-idle observation (see
 * UA_SELECT_IDLE_* / utxo_apply_select_idle_note in
 * utxo_apply_stage_fallback.c) — the height (and why) utxo_apply is currently
 * stuck trying to select/read a block to apply. -1 / false when the stage has
 * never gone select-idle. This is NOT necessarily near the active tip: a
 * stale-script/coin-backfill replay can rewind the stage's cursor to
 * re-derive an arbitrary earlier height. Recovery Conditions (see
 * conditions/have_data_unreadable.h) consume this to locate an unreadable/
 * corrupt local body anywhere in the chain, not just tip+1. Atomic reads;
 * see CLAUDE.md "Adding state introspection". */
int64_t utxo_apply_stage_select_idle_height(void);
bool utxo_apply_stage_select_idle_is_read_failure(void);

/* The height utxo_apply is CURRENTLY held at by a genuine apply-candidate
 * anomaly (the block map / durable-or-visible parent / on-disk body disagreeing
 * with the ok-bound height-keyed verdict) — or -1 when no such hold is live.
 *
 * Unlike utxo_apply_stage_select_idle_height() above, which is a last-observed
 * high-water reading that survives the hold ending, this reports LIVE state: the
 * liveness comes from the `utxo_apply.apply_candidate_anomaly` blocker the hold
 * itself publishes, and the selection path clears that blocker the instant a
 * candidate resolves (utxo_apply_stage_fallback.c). Recovery Conditions consume
 * it to distinguish "the fold is wedged right now, at this height" from "the
 * fold is merely slow", which is otherwise indistinguishable from a tip that has
 * simply not advanced yet. Atomic + in-memory registry reads; no I/O. */
int64_t utxo_apply_stage_candidate_anomaly_hold_height(void);

uint64_t utxo_apply_stage_verified_total(void);
uint64_t utxo_apply_stage_spend_unknown_total(void);
uint64_t utxo_apply_stage_utxo_collision_total(void);
uint64_t utxo_apply_stage_value_overflow_total(void);
uint64_t utxo_apply_stage_upstream_failed_total(void);
uint64_t utxo_apply_stage_internal_error_total(void);
uint64_t utxo_apply_stage_reorg_unwound_total(void);
uint64_t utxo_apply_stage_reorg_audit_total(void);
uint64_t utxo_apply_stage_outputs_added_total(void);
uint64_t utxo_apply_stage_outputs_spent_total(void);

void utxo_apply_stage_set_reader(utxo_apply_reader_fn fn, void *user);
void utxo_apply_stage_set_lookup(utxo_apply_lookup_fn fn, void *user);

/* True iff the production coins_kv-backed prevout resolver is installed (see
 * the commit-invariant (a) gate — a synthetic test lookup makes spends delete
 * no coins_kv row, so (a) must be skipped there). */
bool utxo_apply_stage_lookup_is_live(void);

bool utxo_apply_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_UTXO_APPLY_STAGE_H */
