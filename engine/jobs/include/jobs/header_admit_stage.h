/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * header_admit_stage — reducer Job stage.
 *
 * The first concrete staged-sync consumer of progress.kv. Operates in
 * authoritative mode: reads from the live in-memory active chain, writes
 * its durable `header_admit_log` row to progress.kv, and admits headers
 * into the reducer-owned block index.
 *
 * Cursor semantics
 * -----------------
 *   cursor = next height to admit
 *   cursor_in == 0  → about to admit genesis
 *   cursor_out      == cursor_in + 1 on JOB_ADVANCED
 *
 * Idempotency
 * ------------
 * Each step admits one header at height `cursor_in`. Writes to
 * `header_admit_log` use `INSERT OR REPLACE` keyed on height, so a
 * replay after crash-mid-step re-emits the same row (or a different
 * one if the chain has reorged through that height in between).
 *
 * The F-2 `stage` primitive wraps each step in a `BEGIN IMMEDIATE`
 * transaction on the progress.kv handle, so the log insert + cursor
 * UPSERT commit atomically.
 *
 * Schema
 * -------
 *   CREATE TABLE IF NOT EXISTS header_admit_log (
 *     height      INTEGER PRIMARY KEY,
 *     hash        BLOB    NOT NULL,
 *     parent_hash BLOB,              -- NULL for genesis
 *     admitted_at INTEGER NOT NULL
 *   );
 *
 * Lifecycle
 * ----------
 * `init` binds the stage to a `main_state` and ensures the schema.
 * `step_once` runs one step (used both by the supervisor's periodic
 * tick and by the unit tests). `shutdown` disposes the stage. The
 * supervisor wiring lives in `engine/composition/src/boot_services.c` —
 * `staged.header_admit` is registered with `period_secs=2`, and its
 * on_tick drains up to `HEADER_ADMIT_BATCH_PER_TICK` steps before
 * yielding. */

#ifndef ZCL_SERVICES_HEADER_ADMIT_STAGE_H
#define ZCL_SERVICES_HEADER_ADMIT_STAGE_H

#include "util/stage.h"

#include <stdbool.h>
#include <stdint.h>

struct main_state;
struct block_index;
struct uint256;
struct json_value;

/* Max steps drained per supervisor tick. Bounded to keep contention
 * on progress.kv low and to avoid starving other supervisor children. */
#define HEADER_ADMIT_BATCH_PER_TICK  500

/* Bind the stage to `ms` (the live chainstate) and ensure the
 * header_admit_log schema in progress.kv. Idempotent — a second call
 * returns true if already initialised against the same `ms`. Requires
 * `progress_store_open` to have succeeded first. */
bool header_admit_stage_init(struct main_state *ms);

/* Run one stage step. Returns the stage result code. Safe to call before
 * init (returns JOB_IDLE). */
job_result_t header_admit_stage_step_once(void);

/* Drain up to `max_steps` consecutive ADVANCE steps. Stops early on
 * IDLE, BLOCKED, or ERROR. Returns the count of ADVANCED steps. */
int header_admit_stage_drain(int max_steps);

/* Disarm + free. Idempotent. */
void header_admit_stage_shutdown(void);

/* Observability. */
uint64_t header_admit_stage_cursor(void);
/* Step-timing EWMA (us); see util/stage.h. 0 if never stepped. */
int64_t  header_admit_stage_step_us_ewma(void);
uint64_t header_admit_stage_admitted_total(void);
/* Count of reorg-rewinds: each time the active chain reorged below the
 * cursor, the cursor was rewound to the fork point so the stale log rows
 * get re-admitted (INSERT OR REPLACE) with the canonical hashes. */
uint64_t header_admit_stage_reorg_rewind_total(void);
/* Number of bounded active-chain/log consistency audits. A drain transaction
 * performs exactly one even when it admits hundreds of headers. */
uint64_t header_admit_stage_reorg_audit_total(void);
/* Number of active-window heights actually compared by those audits. Heights
 * above the raw lookahead window are known NULL and deliberately skipped. */
uint64_t header_admit_stage_reorg_audit_height_checks(void);
/* Count of block_index entries the stage CREATED from staged raw header
 * bytes (the reducer producer path). */
uint64_t header_admit_stage_produced_total(void);
bool header_admit_stage_has_record(int32_t height,
                                   const struct uint256 *hash);

/* `z23 dumpstate header_admit` (dump-state convention). */
bool header_admit_stage_dump_state_json(struct json_value *out,
                                         const char *key);

#ifdef ZCL_TESTING
typedef bool (*header_admit_authoritative_hook)(
    struct main_state *ms,
    struct block_index *bi,
    void *user);

void header_admit_stage_set_authoritative_hook(
    header_admit_authoritative_hook hook,
    void *user);
#endif

#endif /* ZCL_SERVICES_HEADER_ADMIT_STAGE_H */
