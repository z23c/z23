/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_drive_guard — a tiny process-global re-entrancy guard that marks
 * when a SYNCHRONOUS reducer drive (reducer_ingest_block, on the mining /
 * submitblock / rebuild thread) is actively draining the staged Job pipeline.
 *
 * Why: the staged_sync_supervisor ticks the same stage drains every ~2s on
 * its own thread. The stages share the active-chain window (extended/collapsed
 * by reducer_extend_window_to_candidate / active_chain_move_window_tip) which
 * is NOT covered by the per-stage progress.kv txn lock. If the supervisor
 * drains a stage WHILE reducer_ingest_block is mid-drive, the two races on that
 * window — a self-mined block can transiently fail to resolve and a stage then
 * records a PERMANENT failure row the forward-only cursor never re-evaluates.
 *
 * The supervisor checks reducer_drive_active() at the top of its per-stage tick
 * and skips that tick while a synchronous drive is in progress. This is a NO-OP
 * for live network sync, where reducer_ingest_block is never on the path (the
 * supervisor is the sole driver), so the flag is always 0.
 *
 * Counter (not bool) so nested/repeated enters are safe. */
#ifndef ZCL_UTIL_REDUCER_DRIVE_GUARD_H
#define ZCL_UTIL_REDUCER_DRIVE_GUARD_H

#include <stdbool.h>
#include <stdint.h>

/* Mark a synchronous reducer drive as entered/exited. Balanced pairs. */
void reducer_drive_enter(void);
void reducer_drive_exit(void);

/* Like reducer_drive_enter(), but names the driver for the watchdog and
 * dumpstate. `label` MUST be a string literal / static string (stored by
 * pointer, read from other threads). The outermost enter wins the label. */
void reducer_drive_enter_labeled(const char *label);

/* True while at least one synchronous reducer drive is in progress. */
bool reducer_drive_active(void);

/* Microseconds since the OUTERMOST drive entered; 0 when inactive.
 * Observational only — feeds the drive-age watchdog and dumpstate. */
int64_t reducer_drive_age_us(void);

/* Static label of the active drive ("" when inactive/unlabeled). */
const char *reducer_drive_label(void);

#endif /* ZCL_UTIL_REDUCER_DRIVE_GUARD_H */
