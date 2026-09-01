/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validate_headers_stage — reducer Job stage.
 *
 * Consumes `header_admit_log` and
 * records the result of full header validation in `validate_headers_log`.
 * A passing stage row also marks the in-memory block_index entry as at least
 * BLOCK_VALID_HEADER.
 *
 * Validation pipeline (per height)
 * --------------------------------
 *  1. Read `(height, hash)` from `header_admit_log`.
 *  2. Look up `active_chain_at(ms, height)` for the in-memory
 *     `struct block_index` (carries nVersion / nBits / nNonce /
 *     hashMerkleRoot / nTime / nFile / nDataPos and, on normal header
 *     ingress, the Equihash solution).
 *  3. Validate cheap fields first:
 *       - nVersion ≥ MIN_BLOCK_VERSION
 *       - CheckProofOfWork(hash, nBits)   (target check, no Equihash)
 *  4. Prefer the indexed header solution; when restart/load paths have
 *     evicted it from RAM, load the persisted block-index record by hash.
 *  5. Validate the Equihash solution against (N, K) from the active
 *     chain params at this height.
 *  6. Write a `validate_headers_log` row in the same `BEGIN IMMEDIATE`
 *     transaction that bumps the cursor.
 *
 * Worker pool
 * -----------
 * Steps 3–5 are CPU+I/O bound (Equihash is ~ms per block). The stage
 * runs a pool of `VH_POOL_SIZE` pthread workers; each step
 * submits up to `VH_BATCH_SIZE` jobs, awaits them all, then writes the
 * batch + cursor bump atomically. Workers are created at init and
 * joined at shutdown. The width is NOT fixed: it is chosen at init by
 * vh_runtime_pool_size()/vh_runtime_batch_size() and re-synced between
 * steps (vh_pool_sync_width) so a catch-up-gated widening
 * (ZCL_VH_CATCHUP_POOL_SIZE) or an offline fold widening
 * (ZCL_VH_POOL/ZCL_VH_BATCH) can engage mid-run. Widening changes HOW
 * MANY headers are verified concurrently, never WHAT is checked — at a
 * normal at-tip node every width is the compile-time default.
 *
 * Cursor floor
 * ------------
 * The stage never validates beyond the header_admit cursor. If
 * `vh_cursor + VH_BATCH_SIZE > header_admit_cursor`, the batch shrinks
 * to whatever is available; if zero, the step returns JOB_IDLE.
 *
 * Schema
 * -------
 *   CREATE TABLE IF NOT EXISTS validate_headers_log (
 *     height       INTEGER PRIMARY KEY,
 *     hash         BLOB    NOT NULL,
 *     ok           INTEGER NOT NULL,   -- 0 = failed, 1 = passed
 *     fail_reason  TEXT,               -- NULL when ok=1
 *     validated_at INTEGER NOT NULL
 *   );
 *
 * Lifecycle
 * ---------
 * `init` binds the stage to a `main_state`, ensures the schema, and
 * spins up the worker pool. `step_once` runs one batched step.
 * `shutdown` joins the workers, disposes the stage, and resets per-init
 * observability counters (the persisted cursor + log rows are not
 * touched). When frontier validation is idle, the stage makes one bounded
 * sweep over persisted failed rows below the validate cursor so upgraded
 * validation logic can clear stale failure rows without cursor rewinds.
 * The supervisor wiring lives in
 * `engine/composition/src/boot_services.c` — `staged.validate_headers` is
 * registered with `period_secs=2`. */

#ifndef ZCL_SERVICES_VALIDATE_HEADERS_STAGE_H
#define ZCL_SERVICES_VALIDATE_HEADERS_STAGE_H

#include "util/stage.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct main_state;
struct block_index;
struct uint256;
struct json_value;

#define VH_POOL_SIZE         4
#define VH_BATCH_SIZE       64
#define VH_MAX_REASON       64
#define VH_BATCH_PER_TICK   64

/* Offline mint/refold fold widening (validate_headers_tuning.c). These apply
 * ONLY while refold_cadence_active(); a live node always runs VH_POOL_SIZE /
 * VH_BATCH_SIZE. Verdict-identical at any width — Equihash verification is a
 * pure function of the header. */
#define VH_FOLD_POOL_DEFAULT   16
#define VH_FOLD_BATCH_DEFAULT 256
#define VH_MAX_POOL           128
#define VH_MAX_BATCH         4096

/* Live catch-up widening (validate_headers_tuning.c). Applies ONLY while
 * catchup_cadence_active() (peers connected AND tip gap >= threshold) and no
 * fold is in progress: the pool scales to min(nproc, VH_CATCHUP_POOL_CAP) or
 * the ZCL_VH_CATCHUP_POOL_SIZE override, and the supervisor's fan-out
 * containment (A12, stage_effective_batch) lets the stage drain up to
 * VH_CATCHUP_STEP_MULT x its normal steps per tick so per-tick wall time
 * stays bounded by the same work at a wider width. The per-STEP batch stays
 * VH_BATCH_SIZE — only concurrency and step count change. Verdict-identical
 * at any width. */
#define VH_CATCHUP_POOL_CAP   16
#define VH_CATCHUP_STEP_MULT   4

/* Test seam: injectable validator. The default validator runs the full
 * PoW + Equihash pipeline against persisted header records; tests inject a stub that
 * decides purely from in-memory fields.
 *
 * Contract: writes a NUL-terminated reason string into `out_reason`
 * on failure (≤ VH_MAX_REASON-1 chars). On success may leave it empty.
 * Returns true on pass. Must be reentrant-safe (called from N workers
 * concurrently). */
typedef bool (*vh_validator_fn)(const struct block_index *bi,
                                 const char *datadir,
                                 char *out_reason,
                                 size_t out_reason_size,
                                 void *user);

/* Bind the stage to `ms`, ensure the validate_headers_log schema, and
 * launch the worker pool at the current runtime width (VH_POOL_SIZE on a
 * normal node). Idempotent — a second call against the
 * same `ms` returns true. Requires `progress_store_open` first. */
bool validate_headers_stage_init(struct main_state *ms);

/* Inject a non-default validator. Must be called BETWEEN init and the
 * first step. Reset to the default by `shutdown`. */
void validate_headers_stage_set_validator(vh_validator_fn fn, void *user);

job_result_t validate_headers_stage_step_once(void);
int            validate_headers_stage_drain(int max_steps);
void           validate_headers_stage_shutdown(void);

uint64_t validate_headers_stage_cursor(void);
/* Step-timing EWMA (us); see util/stage.h. 0 if never stepped. */
int64_t  validate_headers_stage_step_us_ewma(void);

/* Catch-up drain-steps cap for the supervisor's fan-out containment (A12).
 * Returns `normal_steps` UNCHANGED unless catchup_cadence_active(); when
 * active, returns normal_steps scaled by the pool widening actually in force
 * (vh_runtime_pool_size() / VH_POOL_SIZE), clamped to [1, VH_CATCHUP_STEP_MULT]
 * — so an operator who pins ZCL_VH_CATCHUP_POOL_SIZE at/below VH_POOL_SIZE
 * gets NO step raise, and the per-tick Equihash volume never exceeds
 * VH_CATCHUP_STEP_MULT x baseline while the workers to run it in the same
 * wall time exist. Implemented in validate_headers_tuning.c. */
int validate_headers_stage_catchup_step_cap(int normal_steps);
uint64_t validate_headers_stage_passed_total(void);
uint64_t validate_headers_stage_failed_total(void);

/* Rising-edge count of "header mark refused" WARNs emitted — one per mark-
 * failure streak (the storm→typed-blocker throttle). Test hook + diagnostics;
 * a value that stays 1 while many JOB_IDLE steps run proves the storm is gone. */
int64_t validate_headers_stage_mark_fail_warn_count(void);

/* Test-only: the current failure-recheck floor (lowest height the recheck pass
 * revisits). See the Task A #12 floor-pin regression test. */
int64_t validate_headers_stage_recheck_floor_for_test(void);

bool validate_headers_stage_has_pass_record(int32_t height,
                                            const struct uint256 *hash);

/* On-demand, single-header form of the reducer stage's per-height validation.
 * Resolves the block index at `height` (active_chain_at, then the header-tip
 * ancestor walk — the SAME resolver the batched stage uses), runs the FULL
 * canonical validator (PoW target + Equihash solution), and on pass durably
 * records a validate_headers_log PASS row at (height, that header's own hash).
 * Idempotent: a no-op returning true when a pass row already exists. Returns
 * true iff a durable pass record is present after the call.
 *
 * This is the instant-on seam: a headers-first (--importblockindex / fast-sync)
 * substrate bulk-loads the block index but never runs the forward reducer, so it
 * carries NO validate_headers_log pass records. Before binding the compiled
 * checkpoint (the -4 header-bootstrap crypto anchor needs a full-Equihash pass
 * record at exactly the checkpoint height), the install path calls this for the
 * ONE checkpoint header — genuinely PoW-validating the real imported header,
 * exactly as a P2P node's stage would have. NOT a bypass: a wrong-block or
 * PoW-invalid header at the checkpoint height fails the validator (no record
 * written) and the bind still refuses. Standalone — safe to call before
 * validate_headers_stage_init (uses only the progress store + `ms` + the
 * canonical validator + the log store). Requires progress_store_open first. */
bool validate_headers_stage_ensure_pass_record(struct main_state *ms,
                                               int32_t height);

struct validate_headers_window_report {
    bool available;
    bool complete;
    int64_t start_height;
    int64_t end_height;
    int64_t expected_count;
    int64_t checked_count;
    int64_t failed_count;
    int64_t first_failed_height;
    char first_fail_reason[VH_MAX_REASON];
};

bool validate_headers_stage_window_report(
    int64_t start_height,
    int64_t end_height,
    struct validate_headers_window_report *out);

bool validate_headers_stage_dump_state_json(struct json_value *out,
                                             const char *key);

#endif /* ZCL_SERVICES_VALIDATE_HEADERS_STAGE_H */
