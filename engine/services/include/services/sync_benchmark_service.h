/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sync_benchmark_service — the zcl.sync_benchmark.v1 phase-timed receipt.
 *
 * Makes "sync is fast" a measured, regression-gated number. A process-wide
 * singleton instrument stamps a monotonic clock at the boundaries of the eight
 * sync phases and accumulates resource counters, then writes ONE durable
 * receipt to <datadir>/sync_benchmark.json at the natural completion point
 * (mirrors soak_attestation_service's datadir-evidence pattern). The receipt is
 * the input the future MVP "sync fast" criterion consumes.
 *
 * Honesty contract (never a number the path did not actually measure):
 *   - A phase that was never stamped is emitted as null with a reason.
 *   - A partial / aborted sync writes a receipt with complete=false and an
 *     incomplete_reason, carrying only the phases that DID finish — never a
 *     receipt implying a full fast sync happened when it did not.
 *
 * Source signals (real, not fabricated):
 *   - per-phase elapsed_ms: monotonic clock deltas stamped at boundaries.
 *   - bytes_reused: the ROM journal resume path's durable-chunk accounting
 *     (net/rom_journal.h — a set bit always implies verified, on-disk bytes).
 *   - peak_rss_bytes: sampled from os_proc_mem_read at every phase boundary.
 *
 * Threading: a leaf mutex guards all state. Every entry point is safe from any
 * non-reducer-drive thread (the artifact-fetch command worker, tests). It never
 * touches the reducer drive, csr, or coins_kv.
 */

#ifndef ZCL_SYNC_BENCHMARK_SERVICE_H
#define ZCL_SYNC_BENCHMARK_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;

/* The eight measured sync phases, in wire order. Kept in lockstep with the
 * timings_ms field names in the zcl.sync_benchmark.v1 schema. */
enum sync_bench_phase {
    SYNC_BENCH_PEER_DISCOVERY = 0,
    SYNC_BENCH_HEADERS,
    SYNC_BENCH_MANIFEST,
    SYNC_BENCH_ARTIFACT_DOWNLOAD,
    SYNC_BENCH_ARTIFACT_VERIFY,
    SYNC_BENCH_INSTALL,
    SYNC_BENCH_TAIL_DOWNLOAD,
    SYNC_BENCH_TAIL_FOLD,
    SYNC_BENCH_PHASE_COUNT
};

/* Arm the instrument with this process's datadir and reset all timing/counter
 * state, stamping t0 (the monotonic origin from which t_ready / t_sovereign are
 * derived). Idempotent; passing NULL/"" disables receipt writing but still
 * lets phase stamps accumulate (dump-only mode). */
void sync_benchmark_init(const char *datadir);

/* Stamp the start of `phase`. A second begin without an intervening end just
 * re-stamps the start (last-writer-wins). Samples peak_rss. */
void sync_benchmark_phase_begin(enum sync_bench_phase phase);

/* Stamp the end of `phase`, recording elapsed_ms = now - its begin stamp
 * (clamped to >= 0). A no-op if the phase was never begun. Samples peak_rss. */
void sync_benchmark_phase_end(enum sync_bench_phase phase);

/* Record the derived milestones as monotonic ms since t0. Idempotent
 * (last-writer-wins). Until called, the corresponding timing is null. */
void sync_benchmark_mark_ready(void);
void sync_benchmark_mark_sovereign(void);

/* Resource counters. Each accumulates (adds to the running total); the first
 * call on a counter also flips it from "unmeasured" (null) to measured. */
void sync_benchmark_note_downloaded(uint64_t bytes);
void sync_benchmark_note_reused(uint64_t bytes);
void sync_benchmark_note_redownloaded(uint64_t bytes);

/* Artifact identity (the fetched artifact's chunk_root as lowercase hex, or any
 * bounded identifier). Copied; NULL/"" leaves artifact_id null. */
void sync_benchmark_set_artifact(const char *artifact_id);

/* Build the full zcl.sync_benchmark.v1 receipt into `out` (caller owns it;
 * json_set_object is called first). `complete` marks a full vs partial sync;
 * `incomplete_reason` (may be NULL) is emitted only when complete=false.
 * Returns false only if `out` is NULL. This is the readable surface. */
bool sync_benchmark_build_receipt(struct json_value *out, bool complete,
                                  const char *incomplete_reason);

/* Write the receipt durably to <datadir>/sync_benchmark.json (atomic rename +
 * fsync). Returns false on a missing datadir, a format overflow, or an IO
 * failure (logged). Writing a receipt does not reset the instrument. */
bool sync_benchmark_write_receipt(bool complete, const char *incomplete_reason);

/* State dump (see CLAUDE.md "Adding state introspection"). Emits the current
 * receipt marked complete iff tail_fold finished and t_sovereign is set. */
bool sync_benchmark_dump_state_json(struct json_value *out, const char *key);

/* Reset global state for tests only. */
void sync_benchmark_reset_for_test(void);

#endif /* ZCL_SYNC_BENCHMARK_SERVICE_H */
