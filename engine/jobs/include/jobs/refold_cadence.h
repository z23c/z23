/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * refold_cadence — the mint/refold fold-cadence override.
 *
 * A `-mint-anchor` mint or a `-refold-*` fold re-walks the chain from
 * genesis/anchor OFFLINE. Its throughput is bounded partly by the stage-drain
 * cadence: how many blocks each reducer stage folds per drain (the batch) and,
 * for the supervisor-driven refold, how often the drain runs (the tick period).
 * A LARGER per-drain batch drops the fsync/ext4-journal-commit cadence (the
 * genesis fold's dominant wait — the drive thread otherwise blocks in
 * jbd2_log_wait_commit), and a SHORTER supervisor tick lets the stages drive
 * more often. Neither changes WHAT a stage checks or writes.
 *
 * SAFETY — the override is GATED on refold_cadence_active(): true ONLY when a
 * from-genesis/from-anchor refold is in progress (refold_in_progress()) OR the
 * `-mint-anchor` fold ceiling is set (mint_fold_ceiling_get() != NO_CEILING).
 * On a NORMAL live node BOTH are false, so every accessor returns its unmodified
 * argument / the inert sentinel and the live hot path is BYTE-FOR-BYTE
 * unchanged. This is the load-bearing safety property, pinned by
 * test_refold_cadence: normal mode MUST stay batch=<stage default> / period=2s.
 *
 * The folded coins/anchor/nullifier state is consensus-identical at ANY cadence
 * — only the commit cadence and the call's latency differ. The mint's terminal
 * SHA3==checkpoint + count hard-assert (boot_mint_anchor.c) certifies this on
 * every run regardless of the batch/period chosen here.
 *
 * TUNABLE (only while active):
 *   ZCL_REFOLD_DRAIN_BATCH  blocks/stage/drain   default 2000  clamp [1,1000000]
 *   ZCL_REFOLD_TICK_MS      supervisor tick (ms) default  250  clamp [1,60000]
 */

#ifndef ZCL_JOBS_REFOLD_CADENCE_H
#define ZCL_JOBS_REFOLD_CADENCE_H

#include <stdbool.h>
#include <stdint.h>

/* Accelerated-cadence defaults (used when active + the env var is unset). */
#define REFOLD_CADENCE_DEFAULT_DRAIN_BATCH 2000
#define REFOLD_CADENCE_DEFAULT_TICK_MS      250

/* True iff a mint/refold offline fold is active. Cheap: two atomic reads
 * (refold_in_progress cache + mint_fold_ceiling atomic). False on a normal
 * live node → every accessor below is inert. */
bool refold_cadence_active(void);

/* Per-stage drain batch. Returns `normal_batch` UNCHANGED when inactive; when
 * active, returns ZCL_REFOLD_DRAIN_BATCH (default 2000, clamped). */
int refold_cadence_drain_batch(int normal_batch);

/* Supervisor tick period in microseconds. Returns 0 when inactive (=> the
 * caller uses its normal period_secs, unchanged); when active, returns
 * ZCL_REFOLD_TICK_MS * 1000 (default 250ms, clamped). */
int64_t refold_cadence_tick_period_us(void);

#endif /* ZCL_JOBS_REFOLD_CADENCE_H */
