/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * body_fetch_stage — reducer Job stage.
 *
 * Consumes `validate_headers_log` and
 * records, per height, whether the block body is observable on disk.
 * This stage is an authoritative reducer input, but it does not fetch from
 * peers directly; `msg_blocks` and the block source policy still own body
 * acquisition while this stage records the durable observation.
 *
 * Per-height behaviour
 * --------------------
 *   1. Read `(height, hash, ok)` from `validate_headers_log`.
 *   2. If validate ok=0 (header failed PoW/Equihash earlier): log a
 *      `source='skipped_invalid'` row, ok=0, advance cursor — there is
 *      no point fetching a body for a known-bad header.
 *   3. Else: join that exact hash to nonfailed best-header ancestry and an
 *      exact parent witness: the visible active slot when present, otherwise
 *      the durable finalized/trusted-base hash. A conflicting active sibling
 *      fails closed.
 *      Then check the body availability flag (`BLOCK_HAVE_DATA`).
 *        - Available: log `source='disk'`, ok=1, advance cursor.
 *        - Not yet available: JOB_IDLE (cursor unchanged). The next
 *          tick will retry; this is the natural backpressure that keeps
 *          body_fetch from racing past msg_blocks.
 *
 * Cursor floor
 * ------------
 * `body_fetch_cursor ≤ validate_headers_cursor` always. If the floor
 * is reached, `step_once` returns JOB_IDLE; the supervisor will retry
 * each tick. The cursor never advances ahead of validate, so we never
 * record body status for a header whose PoW we haven't checked.
 *
 * Schema
 * -------
 *   CREATE TABLE IF NOT EXISTS body_fetch_log (
 *     height       INTEGER PRIMARY KEY,
 *     hash         BLOB    NOT NULL,
 *     source       TEXT    NOT NULL,   -- 'disk' | 'skipped_invalid'
 *     bytes        INTEGER NOT NULL DEFAULT 0,
 *     fetched_at   INTEGER NOT NULL,
 *     ok           INTEGER NOT NULL,   -- 1 = body observed; 0 = skipped
 *     fail_reason  TEXT
 *   );
 *
 * Test seam
 * ----------
 * No injectable validator — tests drive availability by manipulating
 * `block_index.nStatus` on synthetic blocks. Keeps the production path
 * trivial; the BLOCK_HAVE_DATA bit is the only signal we read.
 *
 * Lifecycle
 * ----------
 * `init` binds the stage to a `main_state`, ensures the
 * `body_fetch_log` schema, and stages the cursor primitive. `step_once`
 * runs one step. `shutdown` disposes the stage and clears per-init
 * counters. Supervisor wiring lives in `engine/composition/src/boot_services.c` —
 * `staged.body_fetch` is registered with `period_secs=2`. */

#ifndef ZCL_SERVICES_BODY_FETCH_STAGE_H
#define ZCL_SERVICES_BODY_FETCH_STAGE_H

#include "util/stage.h"

#include <stdbool.h>
#include <stdint.h>

struct main_state;
struct block_index;
struct json_value;
struct sqlite3;
struct uint256;

/* Exact durable-verdict -> live-chain join state shared by body_fetch and its
 * missing-body Condition.  The resolver never scans by height: the target is
 * best-header ancestry at `height`, bound to `expected_hash`; its parent is
 * either the visible active slot or the convention-aware durable finalized
 * hash at height-1. */
enum body_fetch_exact_authority_state {
    BODY_FETCH_EXACT_READY = 0,
    BODY_FETCH_EXACT_HAVE_DATA,
    BODY_FETCH_EXACT_BEST_ABSENT,
    BODY_FETCH_EXACT_BEST_HASH_MISMATCH,
    BODY_FETCH_EXACT_ACTIVE_HASH_MISMATCH,
    BODY_FETCH_EXACT_PARENT_ABSENT,
    BODY_FETCH_EXACT_PARENT_MISMATCH,
    BODY_FETCH_EXACT_AUTHORITY_FAILED,
};

const char *body_fetch_exact_authority_state_name(
    enum body_fetch_exact_authority_state state);

/* Resolve one exact validated target.  Owns cs_main internally.  On the
 * healthy path it uses the active parent.  Only when that slot is absent does
 * it release cs_main, read the durable finalized/trusted-base parent under the
 * progress-store lock, then re-lock and repeat the entire identity proof.
 * Returned block_index objects have process lifetime; callers still read
 * mutable status through block_index_status_load(). */
struct block_index *body_fetch_exact_authority_resolve(
    struct sqlite3 *db, struct main_state *ms, int height,
    const struct uint256 *expected_hash,
    enum body_fetch_exact_authority_state *out_state);

/* Max steps drained per supervisor tick. Each step is one in-memory
 * flag check + one small SQL insert; 500 keeps churn modest while
 * letting a backlog catch up in minutes, not hours. */
#define BODY_FETCH_BATCH_PER_TICK 500

/* Bind the stage to `ms` and ensure the body_fetch_log schema in
 * progress.kv. Idempotent — a second call against the same `ms`
 * returns true. Requires `progress_store_open` to have succeeded
 * first. */
bool body_fetch_stage_init(struct main_state *ms);

/* Run one stage step. Returns the stage result code. Safe to call before
 * init (returns JOB_IDLE). */
job_result_t body_fetch_stage_step_once(void);

/* Drain up to `max_steps` consecutive ADVANCE steps. Stops early on
 * IDLE, BLOCKED, or ERROR. Returns the count of ADVANCED steps. */
int body_fetch_stage_drain(int max_steps);

/* Disarm + free. Idempotent. */
void body_fetch_stage_shutdown(void);

/* Observability. */
uint64_t body_fetch_stage_cursor(void);
/* Step-timing EWMA (us); see util/stage.h. 0 if never stepped. */
int64_t  body_fetch_stage_step_us_ewma(void);
uint64_t body_fetch_stage_observed_total(void);   /* source='disk' rows */
uint64_t body_fetch_stage_skipped_total(void);    /* source='skipped_invalid' */

/* `z23 dumpstate body_fetch` (dump-state convention). */
bool body_fetch_stage_dump_state_json(struct json_value *out,
                                       const char *key);

#endif /* ZCL_SERVICES_BODY_FETCH_STAGE_H */
