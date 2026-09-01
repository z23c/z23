/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_apply_stage_internal — sibling-private declarations shared between
 * utxo_apply_stage.c (the Job, which owns and writes this state) and
 * utxo_apply_stage_dump.c (the native dump-state JSON view, which only reads it).
 * Not a public header. Dump-side access is atomic_load only — the dump runs
 * on native/RPC threads while the supervisor thread steps the stage (see
 * CLAUDE.md "Adding state introspection"). Prefixed g_ua_ so the symbols
 * stay unique at global linkage (proof_validate_stage.c keeps its own
 * static counters with the unprefixed names). */

#ifndef ZCL_JOBS_UTXO_APPLY_STAGE_INTERNAL_H
#define ZCL_JOBS_UTXO_APPLY_STAGE_INTERNAL_H

#include "util/stage.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

struct uint256;
struct block_index;
struct main_state;
struct script_validate_verdict_row;
struct utxo_apply_lookup;

/* Per-status verdict totals (count BLOCKS, not ticks — see the CS-F4 dedup
 * in utxo_apply_stage.c) plus output-flow totals. */
extern _Atomic uint64_t g_ua_verified_total;
extern _Atomic uint64_t g_ua_spend_unknown_total;
extern _Atomic uint64_t g_ua_utxo_collision_total;
extern _Atomic uint64_t g_ua_value_overflow_total;
extern _Atomic uint64_t g_ua_coinbase_protect_total;
extern _Atomic uint64_t g_ua_bad_cb_amount_total;
extern _Atomic uint64_t g_ua_shielded_double_spend_total;
extern _Atomic uint64_t g_ua_shielded_anchor_reject_total;
extern _Atomic uint64_t g_ua_upstream_failed_total;
extern _Atomic uint64_t g_ua_internal_error_total;
extern _Atomic uint64_t g_ua_reorg_unwound_total;
extern _Atomic uint64_t g_ua_total_outputs_added;
extern _Atomic uint64_t g_ua_total_outputs_spent;

/* Step/advance/blocked timestamps + last applied height. */
extern _Atomic int64_t g_ua_last_step_unix;
extern _Atomic int64_t g_ua_last_blocked_unix;
extern _Atomic int64_t g_ua_last_advance_height;

/* Durable-upstream-hole observability. Reaching step_apply's
 * found==0 branch implies next_h < pv_cursor (the cursor guard above it
 * already returned JOB_IDLE otherwise), so a missing proof_validate_log row
 * there is a DURABLE upstream hole — a stale-replay / self-restart
 * artifact — never "not yet". total counts HOLES (bumps on a height
 * transition, like the CS-F4 reject totals count blocks); height/first_unix
 * pin the current/last hole; consec counts consecutive ticks observing it
 * (reset to 0 when the row appears). warn_total counts actually-emitted
 * (un-throttled) WARN lines — test-observable, not dumped. */
extern _Atomic uint64_t g_ua_upstream_hole_total;
extern _Atomic int64_t  g_ua_upstream_hole_height;
extern _Atomic int64_t  g_ua_upstream_hole_first_unix;
extern _Atomic uint64_t g_ua_upstream_hole_consec;
extern _Atomic uint64_t g_ua_upstream_hole_warn_total;

/* Hash-bound verdict refusals: the script_validate_log row at the apply
 * height was provably bound to a DIFFERENT block hash than the one being
 * applied (the header height-splice class). Counts
 * refusal heights via the JOB_BLOCKED path (re-fires per tick are visible
 * in the blocker registry, not here). */
extern _Atomic uint64_t g_ua_label_splice_total;

/* Active-chain window misses at a height whose upstream proof row is already
 * ok. A hash-bound fallback is allowed only when script_validate_log binds the
 * same height to an ok block hash present in the block map, that block has
 * data (or its indexed body re-reads and hash-verifies, allowing a stale
 * cleared HAVE_DATA bit to be refreshed), and it extends either the visible
 * parent or the durable finalized parent witnessed in tip_finalize_log. */
extern _Atomic uint64_t g_ua_window_miss_total;
extern _Atomic int64_t  g_ua_window_miss_height;
extern _Atomic uint64_t g_ua_hash_bound_fallback_total;
extern _Atomic int64_t  g_ua_hash_bound_fallback_height;

bool utxo_apply_reorg_batch_should_audit(void);
void utxo_apply_reorg_batch_reset(void);
extern _Atomic uint64_t g_ua_select_idle_total;
extern _Atomic int64_t  g_ua_select_idle_height;
extern _Atomic int64_t  g_ua_select_idle_reason;

enum utxo_apply_select_idle_reason {
    UA_SELECT_IDLE_NONE = 0,
    UA_SELECT_IDLE_NO_MAIN_STATE,
    UA_SELECT_IDLE_ACTIVE_CHAIN_MISSING,
    UA_SELECT_IDLE_ACTIVE_CHAIN_BODILESS,
    UA_SELECT_IDLE_NO_SCRIPT_HASH,
    UA_SELECT_IDLE_BLOCK_MAP_MISS,
    UA_SELECT_IDLE_HEIGHT_MISMATCH,
    UA_SELECT_IDLE_INDEXED_BODY_MISSING,
    UA_SELECT_IDLE_INDEXED_BODY_READ_FAILED,
    UA_SELECT_IDLE_INDEXED_BODY_HASH_MISMATCH,
    UA_SELECT_IDLE_PARENT_MISMATCH,
    UA_SELECT_IDLE_BLOCK_FAILED,
    UA_SELECT_IDLE_STAGE_READ_FAILED
};

const char *utxo_apply_select_idle_reason_name(
        enum utxo_apply_select_idle_reason reason);
void utxo_apply_select_idle_note(int height,
        enum utxo_apply_select_idle_reason reason,
        const struct block_index *bi);

/* Clear the typed apply-candidate-anomaly blocker
 * ("utxo_apply.apply_candidate_anomaly", Task A). No-op if never raised —
 * safe to call unconditionally on any path that resolves a valid apply
 * candidate (mirrors stage_body_read_hold_clear's clear-on-resolve contract). */
void utxo_apply_select_idle_blocker_clear(void);

/* The live stage handle (NULL before init / after shutdown). The dump reads
 * it lock-free. */
stage_t *utxo_apply_stage_handle(void);

/* Production prevout resolver installed by utxo_apply_stage_init when tests
 * have not injected a custom lookup. Read-only; writes stay in
 * utxo_apply_stage.c. */
bool utxo_apply_stage_lookup_live(const struct uint256 *txid, uint32_t vout,
                                  struct utxo_apply_lookup *out, void *user);
/* Bracket the single-owner cached SQLite prevout reader around one outer
 * utxo_apply batch. begin/end are idempotent and finalize any prior statement. */
void utxo_apply_lookup_batch_begin(struct sqlite3 *db);
void utxo_apply_lookup_batch_end(void);

/* Select the block the apply stage may act on. Prefer active_chain[height];
 * if that slot is missing/bodiless, recover only when script_validate_log
 * already ok-bound this height to a body-present block hash and that candidate
 * extends the visible parent or the durable finalized parent. */
struct block_index *utxo_apply_select_apply_block(
        struct sqlite3 *db, struct main_state *ms, int height,
        const struct script_validate_verdict_row *sv_row);

#endif /* ZCL_JOBS_UTXO_APPLY_STAGE_INTERNAL_H */
